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

#ifdef LEARN_DEBUG
#define learn_dbg cls_dbg
#define learn_err cls_err
#else
#define learn_dbg(...)
#define learn_err(...)
#endif

#define DEFAULT_LEARN_RULE 	(VSENTRY_ACTION_ALLOW | VSENTRY_ACTION_LOG)
#define INVALID_RULE 		(unsigned int)(-1)

static act_t learn_action = {
	.action_bitmap = DEFAULT_LEARN_RULE,
	.name = "learn_act",
	.name_len = 9,
};

typedef struct {
	unsigned int uid;
	unsigned long exec_ino;
	unsigned int rules[CLS_TOTAL_RULE_TYPE];
	void *next;
} cls_uid_prog_pair_t;

static cls_uid_prog_pair_t *head = NULL;

static cls_uid_prog_pair_t *cls_learn_find_pair(unsigned int uid, unsigned long exec_ino)
{
	cls_uid_prog_pair_t *tmp = head;

	while(tmp) {
		if (tmp->uid == uid && tmp->exec_ino == exec_ino)
			return tmp;

		tmp = (cls_uid_prog_pair_t*)tmp->next;
	}

	return NULL;
}

static cls_uid_prog_pair_t *cls_learn_create_pair(unsigned int uid, unsigned long exec_ino)
{
	cls_uid_prog_pair_t *tmp = NULL;

	tmp = heap_calloc(sizeof(cls_uid_prog_pair_t));
	if (!tmp) {
		learn_err("failed to allocate new pair\n");
		return NULL;
	}

	tmp->exec_ino = exec_ino;
	tmp->uid = uid;
	tmp->next = head;

	/* set invalid rule numbers */
	tmp->rules[CLS_IP_RULE_TYPE] = INVALID_RULE;
	tmp->rules[CLS_CAN_RULE_TYPE] = INVALID_RULE;
	tmp->rules[CLS_FILE_RULE_TYPE] = INVALID_RULE;

	learn_dbg("created new pair uid %u ino %lu\n", uid, exec_ino);

	/* set head to the new pair */
	head = tmp;

	return tmp;
}

static int cls_learn_set_new_rule(cls_uid_prog_pair_t *pair, cls_rule_type_e type)
{
	int rule;
	act_t act;

	rule = cls_get_free_rule(type);
	if (rule == VSENTRY_ERROR) {
		learn_err("failed to allocate free %s rule\n", get_type_str(type));
		return VSENTRY_ERROR;
	}

	vs_memset(&act, 0, sizeof(act_t));
	act.action_bitmap = DEFAULT_LEARN_RULE;

	if (cls_add_rule(type, rule, learn_action.name, learn_action.name_len, 0) == VSENTRY_SUCCESS) {
		pair->rules[type] = rule;
		learn_dbg("created new rule %u for pair (%u, %lu)\n", rule, pair->uid, pair->exec_ino);
		return VSENTRY_SUCCESS;
	}

	return VSENTRY_ERROR;
}

int cls_learn_event(cls_rule_type_e type, vsentry_event_t *event)
{
	int ret;
	cls_uid_prog_pair_t *pair = NULL;

	/* check if the pair already exist, if not create one */
	if (event->event_id.kernel)
		pair = cls_learn_find_pair(0, 0);
	else
		pair = cls_learn_find_pair(event->event_id.uid, event->event_id.exec_ino);

	if (!pair) {
		pair = cls_learn_create_pair(event->event_id.uid, event->event_id.exec_ino);
		if (!pair) {
			learn_err("failed learn new event_id\n");
			return VSENTRY_ERROR;
		}
	}

	if (pair->rules[type] == INVALID_RULE) {
		/* we need to find rule for this pair&type */
		ret = cls_learn_set_new_rule(pair, type);
		if (ret != VSENTRY_SUCCESS) {
			learn_err("failed set new rule\n");
			return VSENTRY_ERROR;
		}
	}

	switch (type) {
	case CLS_IP_RULE_TYPE:
		if (event->ip_event.daddr.v4addr != INADDR_BROADCAST) {
			ret = net_cls_add_rule(pair->rules[type], htonl(event->ip_event.daddr.v4addr),
					0xFFFFFFFF, CLS_NET_DIR_DST);
			if (ret == VSENTRY_SUCCESS) {
				/* learn proto */
				ret = ip_proto_cls_add_rule(pair->rules[type], event->ip_event.ip_proto);
				if (ret == VSENTRY_SUCCESS) {
					if (event->ip_event.ip_proto == IPPROTO_TCP)
						ret = port_cls_add_rule(pair->rules[type],
								event->ip_event.dport, IPPROTO_TCP, CLS_NET_DIR_DST);
					else if (event->ip_event.ip_proto == IPPROTO_UDP)
						ret = port_cls_add_rule(pair->rules[type],
								event->ip_event.dport, IPPROTO_UDP, CLS_NET_DIR_DST);
				}
			}
		}
		if (event->ip_event.saddr.v4addr != INADDR_BROADCAST) {
			if (ret == VSENTRY_SUCCESS) {
				ret = net_cls_add_rule(pair->rules[type], htonl(event->ip_event.saddr.v4addr),
						0xFFFFFFFF, CLS_NET_DIR_SRC);
				if (ret == VSENTRY_SUCCESS) {
					if (event->ip_event.ip_proto == IPPROTO_TCP)
						ret = port_cls_add_rule(pair->rules[type],
								event->ip_event.sport, IPPROTO_TCP, CLS_NET_DIR_SRC);
					else if (event->ip_event.ip_proto == IPPROTO_UDP)
						ret = port_cls_add_rule(pair->rules[type],
								event->ip_event.sport, IPPROTO_UDP, CLS_NET_DIR_SRC);
				}
			}
		}
		break;

	case CLS_CAN_RULE_TYPE:
		ret = can_cls_add_rule(pair->rules[type], &event->can_event.can_header, event->dir);
		break;

	case CLS_FILE_RULE_TYPE:
		event->file_event.file_ino = 0;
		event->file_event.ancestor_ino = 0;
		ret = file_cls_add_rule(pair->rules[type], &event->file_event);
		break;

	default:
		return VSENTRY_ERROR;
	}

	if (ret != VSENTRY_SUCCESS) {
		learn_err("failed learn new rule\n");
		return VSENTRY_ERROR;
	}

	ret = uid_cls_add_rule(type, pair->rules[type], pair->uid);

	/* skip prog learn in case of kernel exec code */
	if (ret == VSENTRY_SUCCESS && !event->event_id.kernel && event->event_id.exec_name)
		ret = prog_cls_add_rule(type, pair->rules[type], event->event_id.exec_name,
				pair->exec_ino, vs_strlen(event->event_id.exec_name));

	if (ret == VSENTRY_SUCCESS && type == CLS_FILE_RULE_TYPE && !event->event_id.kernel) {
		learn_dbg("learned exec %s (%lu) file %s (%lu) mode %x rule %u\n",
				event->event_id.exec_name,
				event->event_id.exec_ino,
				get_file_name(&event->file_event),
				event->file_event.file_ino,
				event->file_event.mode,
				pair->rules[type]);
	}

	return ret;
}

int cls_learn_init(void)
{
	/* we need to reset head to NULL incase we were reinit with new DB */
	head = NULL;

	if (!action_cls_search(learn_action.name, learn_action.name_len))
		return action_cls_add(&learn_action);

	return VSENTRY_SUCCESS;
}

void cls_learn_deinit(void)
{
	cls_uid_prog_pair_t *tmp = head;

	while(head) {
		tmp = head;
		head = (cls_uid_prog_pair_t*)head->next;
		learn_dbg("free %p\n", tmp);
		heap_free(tmp);
	}
}
