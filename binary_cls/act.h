#ifndef __ACTION_H__
#define __ACTION_H__

#include <stdbool.h>

/* the following should be used in log_target */
#define LOG_NONE 	0
#define LOG_FILE 	(1<<0)
#define LOG_SYSLOG 	(1<<1)

#define ACTION_NAME_SIZE 32

typedef struct __attribute__ ((aligned(8))) {
	unsigned int 	action_bitmap;
	unsigned int 	log_target;
	unsigned int 	name_len;
	char 		name[ACTION_NAME_SIZE];
} act_t;

int    action_cls_init(unsigned int *head_offset);
int    action_cls_add(act_t *act);
int    action_cls_del(char *act_name, int name_len);
int    action_cls_ref(bool ref, char *act_name, int name_len);
act_t *action_cls_search(char *act_name, int name_len);
int    action_clean_unrefed(void);
#ifdef CLS_DEBUG
void   action_print_act(act_t *act);
void   action_print_list(void);
#endif
#endif /* __ACTION_H__ */
