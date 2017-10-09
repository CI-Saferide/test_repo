#ifndef __FILE_HASH__
#define  __FILE_HASH__

SR_32 sr_file_hash_init(void);
void sr_file_hash_deinit(void);
SR_32 sr_file_hash_update_rule(char *filename, char *exec, char *user, SR_U32 rulenum, SR_U16 actions, SR_8 file_ops);
SR_32 sr_file_hash_delete_all(void);
SR_32 sr_file_hash_exec_for_file(char *filename, SR_U32 (*cb)(char *filename, char *exec, char *user, SR_U32 rulenum, SR_U16 actions, SR_8 file_ops));
void sr_file_hash_print(void);

#endif
