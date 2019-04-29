#ifndef SR_CONFIG_H
#define SR_CONFIG_H

#include "sr_actions_common.h"
#include "sr_sal_common.h"
#include "db_tools.h"
#include "redis_mng.h"

#define MAX_PATH_LEN	4096
#define MAX_ACTION_NAME 64
#define MAX_ADDR_LEN 128
#define MAX_PATH 512
#define MAX_USER_NAME 32
#define DIR_LEN 16
#define	INTERFACE_LEN 64
#define PERM_LEN 4
#define LOG_TARGET_LEN 32

typedef struct sr_action_record {
	char             name[MAX_ACTION_NAME];
	SR_U16 		 actions_bitmap;
	sr_log_target_t  log_target;
	SR_U16 		 rl_actions_bitmap;
	sr_log_target_t  rl_log_target;
} sr_action_record_t;

typedef enum {
	NET_ITEM_ACTION,
	NET_ITEM_SRC_ADDR,
	NET_ITEM_DST_ADDR,
	NET_ITEM_PROTO,
	NET_ITEM_SRC_PORT,
	NET_ITEM_DST_PORT,
	NET_ITEM_UP_RL,
	NET_ITEM_DOWN_RL,
	NET_ITEM_PROGRAM,
	NET_ITEM_USER,
} sr_net_item_type_t;

typedef enum {
	CAN_ITEM_ACTION,
	CAN_ITEM_MSG,
	CAN_ITEM_PROGRAM,
	CAN_ITEM_USER,
} sr_can_item_type_t;

typedef enum {
	FILE_ITEM_ACTION,
	FILE_ITEM_FILENAME,
	FILE_ITEM_PERM,
	FILE_ITEM_PROGRAM,
	FILE_ITEM_USER,
} sr_file_item_type_t;

typedef struct {
	SR_8 proto;
	SR_U16 port;
} port_t;

typedef struct {
	sr_net_item_type_t net_item_type;
	union {
		char    action[MAX_ACTION_NAME];
		char	src_addr[MAX_ADDR_LEN];
		char	dst_addr[MAX_ADDR_LEN];
		SR_U8	proto;
		port_t  port;
		SR_U32  up_rl;
		SR_U32  down_rl;
		char    program[MAX_PATH];
		char    user[MAX_USER_NAME];
	} u;
} net_item_t;

typedef struct sr_net_record {
	SR_U16	rulenum;
	net_item_t net_item;
} sr_net_record_t;

typedef struct {
	SR_U32	id;
	char    dir[DIR_LEN];
	char    inf[INTERFACE_LEN];
} can_msg_t;

typedef struct {
	sr_can_item_type_t can_item_type;
	union {
		char    action[MAX_ACTION_NAME];
		can_msg_t msg;
		char    program[MAX_PATH];
		char    user[MAX_USER_NAME];
	} u;
} can_item_t;

typedef struct sr_can_record {
	SR_U16	rulenum;
	can_item_t can_item;
} sr_can_record_t;

typedef struct {
	sr_file_item_type_t file_item_type;
	union {
		char    action[MAX_ACTION_NAME];
		char	filename[MAX_PATH];
		char	perm[PERM_LEN];
		char    program[MAX_PATH];
		char    user[MAX_USER_NAME];
	} u;
} file_item_t;

typedef struct sr_file_record {
	SR_U16	rulenum;
	file_item_t file_item;
} sr_file_record_t;

SR_32 sr_create_filter_paths(void);
void sr_config_vsentry_db_cb(int type, int op, void *entry);
SR_U32 sr_config_get_mod_state(void);
void sr_config_handle_rule(void *data, redis_entity_type_t type, SR_32 *status);
SR_32 sr_config_handle_action(void *data);

#endif /* SR_CONFIG_H */
