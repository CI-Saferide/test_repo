#ifndef __LEARN_H__
#define __LEARN_H__

int  cls_learn_event(cls_rule_type_e type, vsentry_event_t *event);
void cls_learn_deinit(void);
int  cls_learn_init(void);

#endif /* __LEARN_H__ */
