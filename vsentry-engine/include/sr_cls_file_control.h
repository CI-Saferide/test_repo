#ifndef SR_CLS_FILE_CONTROL_H
#define SR_CLS_FILE_CONTROL_H

#include "sr_cls_file_common.h"

int sr_cls_file_add_rule(char *filename, char *exec, char *user, SR_U32 rulenum, SR_U8 treetop);
int sr_cls_file_del_rule(char *filename, char *exec, char *user, SR_U32 rulenum, SR_U8 treetop);
int sr_cls_file_create(char *filename);
int sr_cls_file_add_remove_filter_path(char *path, SR_BOOL is_add);
cls_file_mem_optimization_t sr_cls_file_control_get_mem_opt(void);
void sr_cls_file_control_set_mem_opt(cls_file_mem_optimization_t i_mem_opt);

#endif /* SR_CLS_FILE_CONTROL_H */
