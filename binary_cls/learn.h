#ifndef __LEARN_H__
#define __LEARN_H__

int  cls_learn_event(cls_rule_type_e type, vsentry_event_t *event, bool atomic);
void cls_learn_free_data(void);
int  cls_learn_set_action(void);

#endif /* __LEARN_H__ */
