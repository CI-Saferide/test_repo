#ifndef __CALSSIFIER_H__
#define __CALSSIFIER_H__

#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <linux/vsentry/vsentry.h>
#include "act.h"

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
	CLS_MODE_ENFROCE,
	CLS_MODE_PERMISSIVE,
	CLS_MODE_LEARN,
	CLS_MODE_TOTAL,
} cls_mode_e;

typedef enum {
	CLS_NET_DIR_SRC,
	CLS_NET_DIR_DST,
	CLS_NET_DIR_TOTAL,
} cls_net_dir_e;

int  cls_init(void *shmem);
int  cls_classify_event(vsentry_ev_type_e ev_type, vsentry_event_t *event, bool atomic);
int  cls_handle_event(vsentry_ev_type_e ev_type, vsentry_event_t *event, bool atomic);
inline int cls_get_mode(void);
int  cls_set_mode(cls_mode_e mode);
int  cls_add_rule(cls_rule_type_e type, unsigned int rule, char *act_name, int act_name_len, unsigned int limit);
int  cls_del_rule(cls_rule_type_e type, unsigned int rule);
int  cls_default_action(unsigned int type, act_t *act);
void cls_print_db(void);

#ifdef CLS_DEBUG

void cls_register_printf(void *func);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
extern int (*printf_func)();
#pragma GCC diagnostic pop

#define cls_printf(fmt, ...) ({                         \
       do {                                             \
	       if (printf_func)                         \
	       	       printf_func(fmt, ##__VA_ARGS__); \
       } while (0);                                     \
})

#define cls_crit(fmt, ...) \
	cls_printf("[CRIT] %s: " fmt, __func__, ##__VA_ARGS__)
#define cls_err(fmt, ...) \
	cls_printf("[ERR] %s: " fmt, __func__, ##__VA_ARGS__)
#define cls_warn(fmt, ...) \
	cls_printf("[WARN] %s: " fmt, __func__, ##__VA_ARGS__)
#define cls_info(fmt, ...) \
	cls_printf("[INFO] %s: " fmt, __func__, ##__VA_ARGS__)
#define cls_dbg(fmt, ...) \
	cls_printf("[DBG] %s: " fmt, __func__, ##__VA_ARGS__)

#else
#define cls_printf(...)
#define cls_crit(...)
#define cls_err(...)
#define cls_warn(...)
#define cls_info(...)
#define cls_dbg(...)

#endif /* CLS_DEBUG */

#endif /* __CALSSIFIER_H__ */
