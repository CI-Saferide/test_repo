#ifndef SR_CONFIG_H
#define SR_CONFIG_H

#include "sr_actions_common.h"
#include "sr_sal_common.h"
#include "db_tools.h"

#define MAX_PATH_LEN	4096
#define MAX_ACTION_NAME 64
#define MAX_ADDR_LEN 128
#define MAX_PATH 512
#define MAX_USER_NAME 32

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

typedef struct {
	sr_net_item_type_t net_item_type;
	union {
		char    action[MAX_ACTION_NAME];
		char	src_addr[MAX_ADDR_LEN];
		char	dst_addr[MAX_ADDR_LEN];
		SR_8	proto;
		SR_U16  src_port;
		SR_U16  dst_port;
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

struct sr_file_record{
	SR_U16						rulenum;						/* rule number */
	SR_U16						rate_action;					/* bitmap of rate exceed actions */
	SR_U32 						max_rate;						/* maximum rate */
	SR_32						uid;							/* user id */
	SR_U16						process_size;					/* process name size in bytes */
	SR_U16						filename_size;					/* filename size in bytes */
	SR_8*						process;						/* process name */
};

struct sr_can_record{		
	SR_U16						rulenum;						/* rule number */
	SR_U32						msg_id;							/* can msg id */
	SR_8						direction;							/* can inbount/outbound */
	SR_U16						rate_action;					/* bitmap of rate exceed actions */
	SR_U32 						max_rate;						/* maximum rate */
	SR_32						uid;							/* user id */
	SR_U16						process_size;					/* process name size in bytes */
	SR_8*						process;						/* process name */
};

SR_32 sr_create_filter_paths(void);
void sr_config_vsentry_db_cb(int type, int op, void *entry);
SR_U32 sr_config_get_mod_state(void);

#endif /* SR_CONFIG_H */
