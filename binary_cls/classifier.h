#ifndef __CALSSIFIER_H__
#define __CALSSIFIER_H__

#include <stddef.h>
#include <stdbool.h>
#include <linux/vsentry/vsentry.h>
#include "act.h"
#include "printf.h"

#ifndef NULL
#define NULL 		0
#endif

#define likely(x) 	__builtin_expect(!!(x), 1)
#define unlikely(x) 	__builtin_expect(!!(x), 0)

typedef struct {
	/* this param holds the hash table offset */
	unsigned int hash_offset;
	/* holds the hash table number of bits */
	unsigned int bits;
	/* holds the any rules offset */
	unsigned int any_offset;
} cls_hash_params_t;

typedef enum {
	CLS_IP_RULE_TYPE,
	CLS_CAN_RULE_TYPE,
	CLS_FILE_RULE_TYPE,
	CLS_TOTAL_RULE_TYPE,
	CLS_ERROR_RULE_TYPE = -1,
} cls_rule_type_e;

typedef enum {
	CLS_NET_DIR_SRC,
	CLS_NET_DIR_DST,
	CLS_NET_DIR_TOTAL,
} cls_net_dir_e;

#define LEARN_RULES_START 	3000

int  cls_init(void *shmem);
int  cls_classify_event(vsentry_ev_type_e ev_type, vsentry_event_t *event);
int  cls_handle_event(vsentry_ev_type_e ev_type, vsentry_event_t *event);
int  cls_get_mode(void);
int  cls_set_mode(vsentry_mode_e mode);
void cls_clear_rules(unsigned int start, unsigned int stop);
int  cls_add_rule(cls_rule_type_e type, unsigned int rule, char *act_name, int act_name_len, unsigned int limit);
int  cls_del_rule(cls_rule_type_e type, unsigned int rule);
int  cls_default_action(unsigned int type, act_t *act, unsigned int limit);
void cls_print_db(void);

#ifdef ENABLE_LEARN
int  cls_get_free_rule(cls_rule_type_e type);
#endif

#endif /* __CALSSIFIER_H__ */
