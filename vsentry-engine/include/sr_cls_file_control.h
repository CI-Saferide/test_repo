#ifndef SR_CLS_FILE_CONTROL_H
#define SR_CLS_FILE_CONTROL_H

int sr_cls_file_add_rule(char *filename, char *exec, char *user, SR_U32 rulenum, SR_U8 treetop);
int sr_cls_file_del_rule(char *filename, char *exec, char *user, SR_U32 rulenum, SR_U8 treetop);
int sr_cls_file_create(char *filename);
int sr_cls_file_add_remove_filter_path(char *path, SR_BOOL is_add);

#endif /* SR_CLS_FILE_CONTROL_H */
