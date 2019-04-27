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
#include "file_cls.h"
#include "aux.h"
#include "learn.h"
#include "lru_cache.h"

#ifndef CLS_DEBUG
#define cls_dbg(...)
#define cls_err(...)
#else
static char *cls_get_mode_str(unsigned int mode)
{
	switch (mode) {
	case VSENTRY_MODE_ENFORCE:
		return "enforce";
	case VSENTRY_MODE_PERMISSIVE:
		return "permissive";
	case VSENTRY_MODE_LEARN:
		return "learn";
	default:
		return "n\a";
	}
}

#endif

#define SEC_IN_USEC 	1000000

typedef struct __attribute__ ((aligned(8))) {
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
typedef struct __attribute__ ((aligned(8))) {
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
			unsigned int log_rl_offset;
			unsigned int cache_offset; 	/* offset to LRU cache */
		};
		unsigned char pad[DATABASE_HEAD_SIZE];
	};
} vsentry_db_head_t;

/* the below struct represent the mapping of rule number to action (per type).
 * each event classification will result a bit array. each index of a set bit
 * in the array will represent an action in this struct */
typedef struct __attribute__ ((aligned(8))) {
	unsigned int action_offset[CLS_TOTAL_RULE_TYPE][MAX_RULES];
	unsigned int rl_offset[CLS_TOTAL_RULE_TYPE][MAX_RULES];
} rules_db_t;

static vsentry_db_head_t *db_head = NULL;
static rules_db_t *rules_db = NULL;
static volatile int cls_lock = 0;
static cls_ratelimit_t *log_rl;

int cls_init(void *shmem)
{
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
		db_head->mode = VSENTRY_MODE_PERMISSIVE;
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

	if (file_cls_init(&db_head->file_hash) != VSENTRY_SUCCESS) {
		cls_err("failed to init file_cls\n");
		return  VSENTRY_ERROR;
	}

	if (!db_head->log_rl_offset) {
		log_rl = heap_calloc(sizeof(cls_ratelimit_t));
		if (!log_rl) {
			cls_err("failed to allocate log_rl\n");
			return VSENTRY_ERROR;
		}
		db_head->log_rl_offset = get_offset(log_rl);
	} else {
		log_rl = get_pointer(db_head->log_rl_offset);
	}

	if (cache_init(&db_head->cache_offset) != VSENTRY_SUCCESS) {
		cls_err("failed to init lru_cache\n");
		return  VSENTRY_ERROR;
	}

	vs_memset(log_rl, 0, sizeof(cls_ratelimit_t));
	log_rl->limit = 250; /* max 250 logs per sec */

#ifdef ENABLE_LEARN
	 if (db_head->mode == VSENTRY_MODE_LEARN)
		cls_learn_init();
#endif

	cls_dbg("classifier mode %s\n", cls_get_mode_str(db_head->mode));

	return VSENTRY_SUCCESS;
}

#ifdef RL_DEBUG
#define rl_dbg cls_dbg
#define rl_err cls_dbg
#else
#define rl_dbg(...)
#define rl_err(...)
#endif

#ifdef __i386__
static inline long u64divu32(long long *divs, long div)
{
	long dum2, rem;

	__asm__("divl %2":"=a"(dum2), "=d"(rem) : "rm"(div), "A"(*divs));

	return dum2;
}

#endif

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
			rl_dbg("%llu delta_ts %llu credit %u size %u\n", ts, delta_ts, rl->credit[dir], size);
		}
		return false;
	}

	rl_dbg("delta_ts %llu limit %llu\n", delta_ts, rl->limit);
	/* figure the added credit */
#ifdef __i386__
	added_credit = (delta_ts * rl->limit);
	added_credit = u64divu32(&added_credit, SEC_IN_USEC);
#else
	added_credit = (delta_ts * rl->limit)/SEC_IN_USEC;
#endif

	if ((credit + added_credit) < size) {
		rl_dbg("rate limit exceeded\n");
		return true;
	}

	new_credit = (credit + (added_credit - size));
	if (new_credit > rl->limit)
		new_credit = rl->limit;

	rl_dbg("new_credit %llu\n", new_credit);
	if (__sync_bool_compare_and_swap(&rl->credit[dir], credit, new_credit))
		__sync_bool_compare_and_swap(&rl->last_ts[dir], last_ts, ts);

	rl_dbg("%llu delta_ts %llu credit %llu size %lu\n", ts, delta_ts, rl->credit[dir], size);

	return false;
}

int cls_classify_event(vsentry_ev_type_e ev_type, vsentry_event_t *event)
{
	int ret = VSENTRY_SUCCESS;
	bit_array_t verdict;
	act_t *act = NULL;
	unsigned short bit;
	unsigned int rl_offset = 0;
	unsigned int size = 0;

	if (event->dir >= DIR_TOTAL) {
		cls_err("invalid dir %u\n", event->dir);
		return VSENTRY_INVALID;
	}

	switch (ev_type) {
	case VSENTRY_CAN_EVENT:
		event->type = CLS_CAN_RULE_TYPE;
		break;

	case VSENTRY_FILE_EVENT:
		event->type = CLS_FILE_RULE_TYPE;
		break;

	case VSENTRY_IP_EVENT:
		event->type = CLS_IP_RULE_TYPE;
		break;

	default:
		cls_err("invalid event\n");
		return VSENTRY_INVALID;
	}

	/* clear bitmap */
	event->act_bitmap = VSENTRY_ACTION_DROP;

#ifdef ENABLE_LEARN
	if (db_head->mode == VSENTRY_MODE_LEARN) {
		/* radix, hash, heap are not thread safe. generally this
		 * is not a problem since during normal mode those are
		 * read only. it become a problem in learn mode, in which
		 * we need to allocate and add new elements */
		if (!vs_spin_trylock(&cls_lock)) {
			event->act_bitmap = VSENTRY_MODE_LEARN;
			return VSENTRY_BUSY;
		}
	}
#endif

	/* set all bits in the initial verdict array */
	ba_set(&verdict);

	/* get uid classification */
	ret = uid_cls_search(event->type, &event->event_id, &verdict);
	if (ret != VSENTRY_SUCCESS || ba_is_empty(&verdict)) {
		cls_err("failed to classify %s uid\n", get_type_str(event->type));
		goto classify_exit;
	}

	/* get prog classification */
	ret = prog_cls_search(event->type, &event->event_id, &verdict);
	if (ret != VSENTRY_SUCCESS || ba_is_empty(&verdict)) {
		cls_err("failed to classify prog (%s) %s\n", get_type_str(event->type),
				event->event_id.exec_name);
		goto classify_exit;
	}

	switch (ev_type) {
	case VSENTRY_CAN_EVENT:
		size = 1;
		ret = can_cls_search(event, &verdict);
		if (ret != VSENTRY_SUCCESS || ba_is_empty(&verdict)) {
			cls_err("failed to classify can\n");
			goto classify_exit;
		}
		break;

	case VSENTRY_FILE_EVENT:
		size = 1;
		ret = file_cls_search(event, &verdict);
		if (ret != VSENTRY_SUCCESS || ba_is_empty(&verdict)) {
			cls_err("failed to classify file\n");
			goto classify_exit;
		}
		break;

	case VSENTRY_IP_EVENT:
		/* local ip address */
		if (event->ip_event.daddr.v4addr == INADDR_ANY || event->ip_event.saddr.v4addr == INADDR_ANY) {
			event->act_bitmap |= VSENTRY_ACTION_ALLOW;
			ret = VSENTRY_SUCCESS;
			goto classify_exit;
		}

#define	IN_LOOPBACK(a) ((((long int) (a)) & 0xff000000) == 0x7f000000)
		/* loop-back ip address */
		if (IN_LOOPBACK(event->ip_event.daddr.v4addr) && IN_LOOPBACK(event->ip_event.saddr.v4addr)) {
			event->act_bitmap |= VSENTRY_ACTION_ALLOW;
			ret = VSENTRY_SUCCESS;
			goto classify_exit;
		}

		/* classify ip_addresses */
		size = event->ip_event.len;
		ret = net_cls_search(&event->ip_event, &verdict);
		if (ret != VSENTRY_SUCCESS || ba_is_empty(&verdict)) {
			cls_err("failed to classify ip\n");
			goto classify_exit;
		}

		/* classify ip_proto */
		ret = ip_proto_cls_search(&event->ip_event, &verdict);
		if (ret != VSENTRY_SUCCESS || ba_is_empty(&verdict)) {
			cls_err("failed to classify ip_proto\n");
			goto classify_exit;
		}

		/* classify ports */
		if (event->ip_event.ip_proto == IPPROTO_TCP ||
				event->ip_event.ip_proto == IPPROTO_UDP) {
			ret = port_cls_search(&event->ip_event, &verdict);
			if (ret != VSENTRY_SUCCESS || ba_is_empty(&verdict)) {
				cls_err("failed to classify port\n");
				goto classify_exit;
			}
		}

		break;

	default:
		goto classify_exit;
	}

	/* we matched a specific rule, get its action */
	bit = ba_ffs(&verdict);
	if (bit == MAX_RULES) {
		cls_err("bitmap is not empty but failed to find action bit\n");
		ret = VSENTRY_NONE_EXISTS;
		goto classify_exit;
	}

	act = get_pointer(rules_db->action_offset[event->type][bit]);
	if (!act)
		goto classify_exit;

//	cls_dbg("rule [%s][%u]: action %s\n", get_type_str(event->type), bit, act->name);

	if (rules_db->rl_offset[event->type][bit])
		rl_offset = rules_db->rl_offset[event->type][bit];

classify_exit:
	switch (db_head->mode) {
	case VSENTRY_MODE_ENFORCE:
		if (!act) {
			/* we didn't matched a specific rule, use the default rules.
			 * we use default rules only when enforcing, otherwise we will
			 * not be able to detect if we need to learn this event */
			act = &db_head->deafults.actions[event->type];
			rl_offset = db_head->deafults.rl_offset[event->type];

//			cls_dbg("using %s default action\n", get_type_str(event->type));
		}

		/* set the action bitmap */
		event->act_bitmap = act->action_bitmap;

		if (event->act_bitmap & VSENTRY_ACTION_ALLOW) {
			/* mark ret value as success as we were able
			 * to classify the even (even if it was set by default action */
			ret = VSENTRY_SUCCESS;
			/* check rule rate limit if action is allow */
			if (rl_offset) {
				if (cls_rl(rl_offset, event->dir, event->ts, size))
					/* rate exceeded .. disallow */
					event->act_bitmap &= ~VSENTRY_ACTION_ALLOW;
			}
		}

		/* check log rate limit */
		if (event->act_bitmap & VSENTRY_ACTION_LOG) {
			if (cls_rl(get_offset(log_rl), event->dir, event->ts, 1))
				/* if exceeded don't log the event */
				event->act_bitmap &= ~VSENTRY_ACTION_LOG;
		}

		break;

	case VSENTRY_MODE_PERMISSIVE:
		/* in permissive mode we always allow */
		event->act_bitmap |= VSENTRY_ACTION_ALLOW;
		ret = VSENTRY_SUCCESS;
		break;

#ifdef ENABLE_LEARN
	case VSENTRY_MODE_LEARN:
		if (!act)
			cls_learn_event(event->type, event);

		vs_spin_unlock(&cls_lock);

		/* in learn mode we always allow */
		event->act_bitmap |= VSENTRY_ACTION_ALLOW;
		ret = VSENTRY_SUCCESS;
		break;
#endif
	default:
		ret = VSENTRY_INVALID;
	}

	return ret;
}

int cls_get_mode(void)
{
	return db_head->mode;
}

int cls_set_mode(vsentry_mode_e mode)
{
	if (mode >= VSENTRY_MODE_TOTAL)
		return VSENTRY_INVALID;

	if (db_head->mode == mode) {
		cls_dbg("mode already set to %s\n", cls_get_mode_str(mode));
		return VSENTRY_SUCCESS;
	}

#ifdef ENABLE_LEARN
	if (db_head->mode == VSENTRY_MODE_LEARN)
		/* when switch from learn mode, we need to free all allocated data memory */
		cls_learn_deinit();

	if (mode == VSENTRY_MODE_LEARN)
		/* when switching to learn mode, we need to add the default learn action */
		cls_learn_init();
#endif

	db_head->mode = mode;

	cls_dbg("set new mode %s\n", cls_get_mode_str(db_head->mode));

	return VSENTRY_SUCCESS;
}

#ifdef ENABLE_LEARN

int cls_get_free_rule(cls_rule_type_e type)
{
	int i;

	for(i=LEARN_RULES_START; i<MAX_RULES; i++) {
		if (!rules_db->action_offset[type][i])
			return i;
	}

	return VSENTRY_ERROR;
}

void cls_clear_rules(unsigned int start, unsigned int stop)
{
	int i, j;

	file_cls_clear_rules(start, stop);
	can_cls_clear_rules(start, stop);
	net_cls_clear_rules(start, stop);
	port_cls_clear_rules(start, stop);
	ip_proto_cls_clear_rules(start, stop);
	uid_cls_clear_rules(start, stop);
	prog_cls_clear_rules(start, stop);

	for (j=0; j<CLS_TOTAL_RULE_TYPE; j++) {
		for (i=start; i<stop; i++) {
			if (rules_db->action_offset[j][i])
				cls_del_rule(j, i);
		}
	}

	/* clear un-refed actions */
	action_clean_unrefed();
}

#endif

int cls_add_rule(cls_rule_type_e type, unsigned int rule, char *act_name, int act_name_len, unsigned int limit)
{
	act_t *db_act;

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
				get_type_str(type), rule, db_act->name);
		action_cls_ref(true, act_name, act_name_len);

		/* set rate-limit only for allow action */
		if (limit && (db_act->action_bitmap & VSENTRY_ACTION_ALLOW)) {
			cls_ratelimit_t *rl = heap_calloc(sizeof(cls_ratelimit_t));
			if (!rl) {
				cls_err("failed to allocate rate-limiter\n");
				return VSENTRY_ERROR;
			}
			rl->limit = limit;
			rules_db->rl_offset[type][rule] = get_offset(rl);
			cls_dbg("created new rate-limiter for %s rule %u with limit %u/sec\n",
					get_type_str(type), rule, rl->limit);
		}
	}

	return VSENTRY_SUCCESS;
}

int cls_del_rule(cls_rule_type_e type, unsigned int rule)
{
	act_t *act;

	if (type >= CLS_TOTAL_RULE_TYPE || rule >= MAX_RULES) {
		cls_err("invalid rule argument\n");

		return VSENTRY_INVALID;
	}

	if (!rules_db->action_offset[type][rule]) {
		cls_err("%s rule %u not assigned to any action\n",
				get_type_str(type), rule);

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

int cls_default_action(unsigned int type, act_t *act, unsigned int limit)
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

	if (limit && (db_act->action_bitmap & VSENTRY_ACTION_ALLOW)) {
		cls_ratelimit_t *rl = heap_calloc(sizeof(cls_ratelimit_t));
		if (!rl) {
			cls_err("failed to allocate rate-limiter\n");
			return VSENTRY_ERROR;
		}

		rl->limit = limit;
		db_head->deafults.rl_offset[type] = get_offset(rl);
	}

#ifdef CLS_DEBUG
	cls_dbg("add default %s rule: ", get_type_str(type));
	action_print_act(db_act);
#endif
	return VSENTRY_SUCCESS;
}

#ifdef CLS_DEBUG
static void cls_print_rules_db(void)
{
	int i, j;
	cls_ratelimit_t *rl;

	cls_printf("rules:\n");

	rl = get_pointer(db_head->deafults.rl_offset[CLS_IP_RULE_TYPE]);
	cls_printf("  default ip rule:   limit %08llu act ", rl?rl->limit:0);
	action_print_act(&db_head->deafults.actions[CLS_IP_RULE_TYPE]);

	rl = get_pointer(db_head->deafults.rl_offset[CLS_CAN_RULE_TYPE]);
	cls_printf("  default can rule:  limit %08llu act ", rl?rl->limit:0);
	action_print_act(&db_head->deafults.actions[CLS_CAN_RULE_TYPE]);

	rl = get_pointer(db_head->deafults.rl_offset[CLS_FILE_RULE_TYPE]);
	cls_printf("  default file rule: limit %08llu act ", rl?rl->limit:0);
	action_print_act(&db_head->deafults.actions[CLS_FILE_RULE_TYPE]);

	for (j=0; j<CLS_TOTAL_RULE_TYPE; j++) {
		for (i=0; i<MAX_RULES; i++) {
			if (rules_db->action_offset[j][i]) {
				act_t *act = get_pointer(rules_db->action_offset[j][i]);
				cls_printf("  rule [%s][%u]: %s", get_type_str(j), i, act->name);
				if (rules_db->rl_offset[j][i]) {
					rl = get_pointer(rules_db->rl_offset[j][i]);
					cls_printf(" limit %llu\n", rl->limit);
				} else
					cls_printf("\n");
			}
		}
	}

	cls_printf("\n");
}
#endif

void cls_print_db(void)
{
#ifdef CLS_DEBUG
	cls_dbg("classifier mode %s\n", cls_get_mode_str(db_head->mode));
	cls_print_rules_db();
	action_print_list();
	uid_print_hash();
	prog_print_hash();
	can_print_hash();
	net_print_tree();
	ip_proto_print_hash();
	port_print_hash();
	file_cls_print_tree();
	heap_print();
#endif
}
