#ifndef __SR_BIN_CLS_ENG_H__
#define __SR_BIN_CLS_ENG_H__

#define DB_FILE 	"/etc/vsentry/db.mem"
#define CLS_FILE 	"/etc/vsentry/cls.bin"
#define DB_FILE_TMP 	"/tmp/db.mem"
#define BIN_CLS_DRV 	"/dev/vs_drv"

int  bin_cls_init(void);
int  bin_cls_deinit(void);
int  bin_cls_reload(void);
int  bin_cls_toggle_enable(void);
int  bin_cls_enable(bool enable);
int  bin_cls_update(bool force);
void cls_print(void);
int  cls_action(bool add, bool allow, bool log, char *name);
int  cls_rule(bool add, unsigned int type, unsigned int rule, char *act_name, unsigned int limit);
int  cls_uid_rule(bool add, unsigned int type, unsigned int rule, unsigned int uid);
int  cls_prog_rule(bool add, unsigned int type, unsigned int rule, unsigned int exec);
int  cls_can_rule(bool add, unsigned int rule, unsigned int msg_id, unsigned int dir, unsigned int if_index);
int  cls_ip_rule(bool add, unsigned int rule, unsigned int addr, unsigned int netmask, unsigned int dir);
int  cls_port_rule(bool add, unsigned int rule, unsigned int port, unsigned int type, unsigned int dir);
int  cls_ip_porto_rule(bool add, unsigned int rule, unsigned int ip_porto);

#endif /* __SR_BIN_CLS_ENG_H__ */
