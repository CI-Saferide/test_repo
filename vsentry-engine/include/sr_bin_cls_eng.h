#ifndef __SR_BIN_CLS_ENG_H__
#define __SR_BIN_CLS_ENG_H__

#include <stdbool.h>

#define DB_FILE 	"/etc/vsentry/db.mem"
#define CLS_FILE 	"/etc/vsentry/cls.bin"
#define BIN_CLS_DRV 	"/dev/vs_drv"

int  bin_cls_init(char *cls, char *db);
void bin_cls_deinit(void);
int  bin_cls_reload(void);
int  bin_cls_toggle_enable(void);
int  bin_cls_enable(bool enable);
int  bin_cls_update(bool force);
int  bin_cls_print_state(void);
void cls_print(void);

#ifdef ENABLE_LEARN
int  bin_cls_learn(bool learn);
#endif

/* DB modification API */
int  cls_action(bool add, bool allow, bool log, char *name);
int  cls_rule(bool add, unsigned int type, unsigned int rule, char *act_name, unsigned int limit);
int  cls_uid_rule(bool add, unsigned int type, unsigned int rule, unsigned int uid);
int  cls_prog_rule(bool add, unsigned int type, unsigned int rule, unsigned long exec, char *exec_name);
int  cls_can_rule(bool add, unsigned int rule, unsigned int msg_id, unsigned int dir, unsigned int if_index);
int  cls_ip_rule(bool add, unsigned int rule, unsigned int addr, unsigned int netmask, unsigned int dir);
int  cls_port_rule(bool add, unsigned int rule, unsigned int port, unsigned int type, unsigned int dir);
int  cls_ip_porto_rule(bool add, unsigned int rule, unsigned int ip_porto);
int  cls_file_rule(bool add, unsigned int rule, char *filename, unsigned long inode, char *mode);

#endif /* __SR_BIN_CLS_ENG_H__ */
