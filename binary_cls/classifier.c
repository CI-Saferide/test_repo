#include <netinet/in.h>
#include <linux/vsentry/vsentry.h>
#include <linux/vsentry/vsentry_drv.h>
#include "classifier.h"
#include "heap.h"
#include "bitops.h"
#include "can_cls.h"
#include "uid_cls.h"
#include "prog_cls.h"
#include "net_cls.h"
#include "port_cls.h"
#include "ip_proto_cls.h"
#include "net_stat_cls.h"
#include "aux.h"
#include "learn.h"

#ifndef CLS_DEBUG
#define cls_dbg(...)
#define cls_err(...)
#endif

#define SEC_IN_USEC 	1000000

typedef struct __attribute__ ((packed, aligned(8))) {
	unsigned long long 	last_ts[DIR_TOTAL];/* the last allowed event */
	unsigned long long 	credit[DIR_TOTAL]; /* current allowance */
	unsigned long long 	limit; 	/* per second */
} cls_ratelimit_t;

typedef struct {
	act_t 		actions[CLS_TOTAL_RULE_TYPE];
	unsigned int 	rl_offset[CLS_TOTAL_RULE_TYPE];
} default_rules_t;

#define DATABASE_HEAD_SIZE 	4096

/* the first 4096 bytes are reserved for the vsentry DB header (persistent) */
typedef struct __attribute__ ((packed, aligned(8))) {
	union {
		struct {
			unsigned int initialized;
			unsigned int mode;
			default_rules_t deafults;
			unsigned int rules_offset; 	/* offset to rules db */
			unsigned int act_offset; 	/* offset to actions db */
			cls_hash_params_t can_hash; 	/* offset to can rules db */
			cls_hash_params_t file_hash; 	/* offset to file rules db */
			cls_hash_params_t ip_hash; 	/* offset to ip rules db */
			cls_hash_params_t prog_hash; 	/* offset to prog rules db */
			cls_hash_params_t user_hash; 	/* offset to user rules db */
			cls_hash_params_t port_hash; 	/* offset to port rules db */
			cls_hash_params_t ip_proto_hash;/* offset to ip_proto rules db */
			cls_hash_params_t net_stat_hash;/* offset to network connections stat */
		};
		unsigned char pad[DATABASE_HEAD_SIZE];
	};
} vsentry_db_head_t;

/* the below struct represent the mapping of rule number to action (per type).
 * each event classification will result a bit array. each index of a set bit
 * in the array will represent an action in this struct */
typedef struct __attribute__ ((packed, aligned(8))) {
	unsigned int action_offset[CLS_TOTAL_RULE_TYPE][MAX_RULES];
	unsigned int rl_offset[CLS_TOTAL_RULE_TYPE][MAX_RULES];
} rules_db_t;

static vsentry_db_head_t *db_head = NULL;
static rules_db_t *rules_db = NULL;
static volatile int cls_lock = 0;
static cls_ratelimit_t *log_rl;

int cls_init(void *shmem)
{
	cls_dbg("\n");

	cls_lock = 0;

	if (sizeof(vsentry_db_head_t) > DATABASE_HEAD_SIZE) {
		cls_err("database head is bigger than it should\n");
		return VSENTRY_ERROR;
	}

	init_heap(shmem + sizeof(vsentry_db_head_t),
		(SHMEM_BUFFER_SIZE - BINS_SIZE - sizeof(vsentry_db_head_t)));

	db_head = (vsentry_db_head_t*)shmem;
	if (!db_head->initialized) {
		int i;

		cls_dbg("resetting heap\n");
		reset_heap();
		db_head->initialized = 1;
		db_head->mode = CLS_MODE_PERMISSIVE;
		/* set the default rules */
		for (i=0; i<CLS_TOTAL_RULE_TYPE; i++) {
			act_t *act = &db_head->deafults.actions[i];

			act->action_bitmap = (VSENTRY_ACTION_DROP | VSENTRY_ACTION_LOG);
		}
	}

	if (!db_head->rules_offset) {
		/* either not allocated or corrupted */
		rules_db = heap_calloc(sizeof(rules_db_t));
		if (!rules_db) {
			cls_err("failed to allocate rules_db\n");
			return VSENTRY_ERROR;
		}

		/* update the classifier database */
		db_head->rules_offset = get_offset(rules_db);
	} else {
		rules_db = get_pointer(db_head->rules_offset);
	}

	if (action_cls_init(&db_head->act_offset) != VSENTRY_SUCCESS) {
		cls_err("failed to init action_cls\n");
		return  VSENTRY_ERROR;
	}

	if (can_cls_init(&db_head->can_hash) != VSENTRY_SUCCESS) {
		cls_err("failed to init can_cls\n");
		return  VSENTRY_ERROR;
	}

	if (uid_cls_init(&db_head->user_hash) != VSENTRY_SUCCESS) {
		cls_err("failed to init uid_cls\n");
		return  VSENTRY_ERROR;
	}

	if (prog_cls_init(&db_head->prog_hash) != VSENTRY_SUCCESS) {
		cls_err("failed to init prog_cls\n");
		return  VSENTRY_ERROR;
	}

	if (net_cls_init(&db_head->ip_hash) != VSENTRY_SUCCESS) {
		cls_err("failed to init net_cls\n");
		return  VSENTRY_ERROR;
	}

	if (port_cls_init(&db_head->port_hash) != VSENTRY_SUCCESS) {
		cls_err("failed to init port_cls\n");
		return  VSENTRY_ERROR;
	}

	if (ip_proto_cls_init(&db_head->ip_proto_hash) != VSENTRY_SUCCESS) {
		cls_err("failed to init ip_proto_cls\n");
		return  VSENTRY_ERROR;
	}

	log_rl = heap_calloc(sizeof(cls_ratelimit_t));
	if (!log_rl) {
		cls_err("failed to allocate log_rl\n");
		return VSENTRY_ERROR;
	}
	log_rl->limit = 250; /* max 250 logs per sec */

	return VSENTRY_SUCCESS;
}

static bool cls_rl(unsigned int rl_offset, unsigned int dir, unsigned long long ts, unsigned int size)
{
	unsigned long long delta_ts, last_ts;
	unsigned long long added_credit, credit, new_credit;
	cls_ratelimit_t *rl;

	if (!rl_offset)
		return false;

	rl = get_pointer(rl_offset);
	if (!rl)
		return false;

	last_ts = rl->last_ts[dir];
	credit = rl->credit[dir];
	delta_ts = ts - last_ts;

	if (delta_ts > SEC_IN_USEC) {
		/* this is the 1st time or full limit cycle completed,
		 * set credit to limit-size and set the last ts */
		if (__sync_bool_compare_and_swap(&rl->credit[dir], credit, (rl->limit - size))) {
			__sync_bool_compare_and_swap(&rl->last_ts[dir], last_ts, ts);
			cls_dbg("%llu delta_ts %llu credit %u size %u\n", ts, delta_ts, rl->credit[dir], size);
		}
		return false;
	}

	/* figure the added credit */
	added_credit = (delta_ts * rl->limit)/SEC_IN_USEC;
	if ((credit + added_credit) < size) {
		cls_dbg("rate limit exceeded");
		return true;
	}

	new_credit = (credit + (added_credit - size));
	if (new_credit > rl->limit)
		new_credit = rl->limit;

	if (__sync_bool_compare_and_swap(&rl->credit[dir], credit, new_credit))
		__sync_bool_compare_and_swap(&rl->last_ts[dir], last_ts, ts);

	cls_dbg("%llu delta_ts %llu credit %u size %u\n", ts, delta_ts, rl->credit[dir], size);

	return false;
}

int cls_classify_event(vsentry_ev_type_e ev_type, vsentry_event_t *event, bool atomic)
{
	int ret = VSENTRY_SUCCESS;
	bit_array_t verdict;
	act_t *act = NULL;
	unsigned short bit;
	unsigned int rl_offset = 0;
	unsigned int size = 0;
#ifdef CLS_DEBUG
	bool is_default = false;
	char *type_name_arr[CLS_TOTAL_RULE_TYPE] = {
		"ip",
		"can",
		"file",
	};
#endif

	if (!event || event->dir >= DIR_TOTAL) {
		cls_err("invalid event\n");
		return VSENTRY_INVALID;
	}

	/* clear bitmap */
	event->act_bitmap = VSENTRY_ACTION_DROP;

	/* set all bits in the initial verdict array */
	ba_set(&verdict);

	switch (ev_type) {
	case VSENTRY_CAN_EVENT:
		size = 1;
		event->type = CLS_CAN_RULE_TYPE;
		ret = can_cls_search(event, &verdict);
		break;

	case VSENTRY_IP_EVENT:
#define	IN_LOOPBACK(a)		((((long int) (a)) & 0xff000000) == 0x7f000000)
		/* local ip address */
		if (event->ip_event.daddr.v4addr == 0 || event->ip_event.saddr.v4addr == 0) {
			event->act_bitmap |= VSENTRY_ACTION_ALLOW;
			return VSENTRY_SUCCESS;
		}

		/* loop-back ip address */
		if (IN_LOOPBACK(event->ip_event.daddr.v4addr) && IN_LOOPBACK(event->ip_event.saddr.v4addr)) {
			event->act_bitmap |= VSENTRY_ACTION_ALLOW;
			return VSENTRY_SUCCESS;
		}

		/* classify ip_addresses */
		size = event->ip_event.len;
		event->type = CLS_IP_RULE_TYPE;
		ret = net_cls_search(&event->ip_event, &verdict);
		if ((ret == VSENTRY_SUCCESS) && !ba_is_empty(&verdict)) {
			/* classify ip_proto */
			ret = ip_proto_cls_search(&event->ip_event, &verdict);
			if ((ret == VSENTRY_SUCCESS) && !ba_is_empty(&verdict)) {
				/* classify ports */
				if (event->ip_event.ip_proto == IPPROTO_TCP ||
						event->ip_event.ip_proto == IPPROTO_UDP)
					ret = port_cls_search(&event->ip_event, &verdict);
			}
		}
		break;

	default:
		event->type = CLS_ERROR_RULE_TYPE;
		ret = VSENTRY_INVALID;
	}

	if (ret != VSENTRY_SUCCESS) {
		cls_err("failed to classify event\n");
		return ret;
	}

	if (!ba_is_empty(&verdict)) {
		/* get uid classification */
		ret = uid_cls_search(event->type, &event->event_id, &verdict);
		if (ret != VSENTRY_SUCCESS) {
			cls_err("failed to classify event\n");
			return ret;
		}

		if (!ba_is_empty(&verdict)) {
			/* get prog classification */
			ret = prog_cls_search(event->type, &event->event_id, &verdict);
			if (ret != VSENTRY_SUCCESS) {
				cls_err("failed to classify event\n");
				return ret;
			}
		}
		/* we matched a specific rule, get its action */
		bit = ba_ffs(&verdict);
		if (bit == MAX_RULES) {
			cls_err("bitmap is not empty but failed to find action bit\n");
			return VSENTRY_NONE_EXISTS;
		}

		act = get_pointer(rules_db->action_offset[event->type][bit]);
		if (rules_db->rl_offset[event->type][bit])
			rl_offset = rules_db->rl_offset[event->type][bit];
	}

	if (!act && db_head->mode == CLS_MODE_ENFORCE) {
		/* we didn't matched a specific rule, use the default rules.
		 * we use default rules only when enforcing, otherwise we will
		 * not be able to detect if we need to learn this event */
		act = &db_head->deafults.actions[event->type];
		rl_offset = db_head->deafults.rl_offset[event->type];
#ifdef CLS_DEBUG
		is_default = true;
#endif
	}

	if (act) {
#ifdef CLS_DEBUG
		if (is_default)
			cls_dbg("using %s default\n", type_name_arr[event->type]);
		else
			cls_dbg("rule [%s][%u]: action %s\n", type_name_arr[event->type],
					bit, act->name);
#endif
		event->act_bitmap = act->action_bitmap;

		/* check rule rate limit if action is drop */
		if (rl_offset && !(event->act_bitmap & VSENTRY_ACTION_ALLOW)) {
			cls_dbg("rl_offset %u\n", rl_offset);
			if (!cls_rl(rl_offset, event->dir, event->ts, size)) {
				cls_dbg("rate limit override with allow\n");
				event->act_bitmap |= VSENTRY_ACTION_ALLOW;
			}
		}

		/* check log rate limit */
		if (event->act_bitmap & VSENTRY_ACTION_LOG) {
			if (cls_rl(get_offset(log_rl), event->dir, event->ts, 1))
				/* if exceeded don't log the event */
				event->act_bitmap &= ~VSENTRY_ACTION_LOG;
		}
	}

	switch (db_head->mode) {
#ifdef ENABLE_LEARN
	case CLS_MODE_LEARN:
		cls_learn_event(event->type, event, atomic);
#endif
	case CLS_MODE_PERMISSIVE:
		/* in permissive/learn mode we always allow */
		event->act_bitmap |= VSENTRY_ACTION_ALLOW;
		break;
	default:
		break;
	}

	return VSENTRY_SUCCESS;
}

int cls_get_mode(void)
{
	return db_head->mode;
}

int cls_set_mode(cls_mode_e mode)
{
#ifdef CLS_DEBUG
	char *mode_str[CLS_MODE_TOTAL] = {
	"enforce",
	"permissive",
#ifdef ENABLE_LEARN
	"learn"
#endif
};
#endif

	if (mode >= CLS_MODE_TOTAL)
		return VSENTRY_INVALID;

	if (db_head->mode == mode) {
		cls_dbg("mode already set to %s\n", mode_str[mode]);
		return VSENTRY_ALREADY_EXISTS;
	}

	cls_dbg("set new mode %s\n", mode_str[mode]);

#ifdef ENABLE_LEARN
	if (db_head->mode == CLS_MODE_LEARN)
		/* when switch from learn mode, we need to free all allocated data memory */
		cls_learn_free_data();

	if (mode == CLS_MODE_LEARN)
		/* when switching to learn mode, we need to add the default learn action */
		cls_learn_set_action();
#endif

	db_head->mode = mode;

	return VSENTRY_SUCCESS;
}

int cls_add_rule(cls_rule_type_e type, unsigned int rule, char *act_name, int act_name_len, unsigned int limit)
{
	act_t *db_act;

#ifdef CLS_DEBUG
	char *type_name_arr[CLS_TOTAL_RULE_TYPE] = {
		"ip",
		"can",
		"file",
	};
#endif

	if (type >= CLS_TOTAL_RULE_TYPE || rule >= MAX_RULES || !act_name) {
		cls_err("invalid rule argument\n");
		return VSENTRY_INVALID;
	}

	db_act = action_cls_search(act_name, act_name_len);
	if (!db_act) {
		cls_err("can't set rule action, no such action %s\n", act_name);
		return VSENTRY_NONE_EXISTS;
	}

	if (!rules_db->action_offset[type][rule]) {
		rules_db->action_offset[type][rule] = get_offset(db_act);
		cls_dbg("created new %s rule %u with action %s\n",
			type_name_arr[type], rule, db_act->name);
		action_cls_ref(true, act_name, act_name_len);
		if (limit) {
			cls_ratelimit_t *rl = heap_calloc(sizeof(cls_ratelimit_t));
			if (!rl) {
				cls_err("failed to allocate rate-limiter\n");
				return VSENTRY_ERROR;
			}
			rl->limit = limit;
			rules_db->rl_offset[type][rule] = get_offset(rl);
			cls_dbg("created new rate-limiter for %s rule %u with limit %u/sec\n",
				type_name_arr[type], rule, rl->limit);
		}
	} else {
		cls_dbg("%s rule %u already assigned to action %s\n",
			type_name_arr[type], rule, db_act->name);
	}

	return VSENTRY_SUCCESS;
}

int cls_del_rule(cls_rule_type_e type, unsigned int rule)
{
	act_t *act;
#ifdef CLS_DEBUG
	char *type_name_arr[CLS_TOTAL_RULE_TYPE] = {
		"ip",
		"can",
		"file",
	};
#endif
	if (type >= CLS_TOTAL_RULE_TYPE || rule >= MAX_RULES) {
		cls_err("invalid rule argument\n");

		return VSENTRY_INVALID;
	}

	if (!rules_db->action_offset[type][rule]) {
		cls_err("%s rule %u not assigned to any action\n",
			type_name_arr[type], rule);

		return VSENTRY_NONE_EXISTS;
	}

	act = get_pointer(rules_db->action_offset[type][rule]);
	action_cls_ref(false, act->name, act->name_len);
	rules_db->action_offset[type][rule] = 0;
	if (rules_db->rl_offset[type][rule]) {
		cls_ratelimit_t *rl = get_pointer(rules_db->rl_offset[type][rule]);
		rules_db->rl_offset[type][rule] = 0;
		heap_free(rl);
	}

	return VSENTRY_SUCCESS;
}

int cls_default_action(unsigned int type, act_t *act)
{
	act_t *db_act;

	switch (type) {
	case CLS_IP_RULE_TYPE:
	case CLS_CAN_RULE_TYPE:
	case CLS_FILE_RULE_TYPE:
		db_act = &db_head->deafults.actions[type];
		break;
	default:
		cls_err("invalid rule type argument\n");
		return VSENTRY_INVALID;
	}

	db_act->action_bitmap = act->action_bitmap;

	return VSENTRY_SUCCESS;
}

static void cls_print_rules_db(void)
{
#ifdef CLS_DEBUG
	int i, j;
	char *type_name_arr[CLS_TOTAL_RULE_TYPE] = {
		"ip",
		"can",
		"file",
	};

	cls_printf("rules:\n");

	cls_printf("  default ip rule:   ");
	action_print_act(&db_head->deafults.actions[CLS_IP_RULE_TYPE]);
	cls_printf("  default can rule:  ");
	action_print_act(&db_head->deafults.actions[CLS_CAN_RULE_TYPE]);
	cls_printf("  default file rule: ");
	action_print_act(&db_head->deafults.actions[CLS_FILE_RULE_TYPE]);

	for (j=0; j<CLS_TOTAL_RULE_TYPE; j++) {
		for (i=0; i<MAX_RULES; i++) {
			if (rules_db->action_offset[j][i]) {
				act_t *act = get_pointer(rules_db->action_offset[j][i]);
				cls_printf("  rule [%s][%u]: %s\n", type_name_arr[j], i, act->name);
			}
		}
	}

	cls_printf("\n");
#endif
}

void cls_print_db(void)
{
	cls_print_rules_db();
	action_print_list();
	uid_print_hash();
	prog_print_hash();
	can_print_hash();
	net_print_tree();
	ip_proto_print_hash();
	port_print_hash();
	heap_print();
}
