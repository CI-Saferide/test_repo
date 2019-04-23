#ifndef SR_CONFIG_H
#define SR_CONFIG_H

#include "sr_actions_common.h"
#include "sr_sal_common.h"
#include "db_tools.h"

#define MAX_PATH_LEN	4096
#define MAX_ACTION_NAME 64

typedef struct sr_action_record {
	char             name[MAX_ACTION_NAME];
	SR_U16 		 actions_bitmap;
	sr_log_target_t  log_target;
	SR_U16 		 rl_actions_bitmap;
	sr_log_target_t  rl_log_target;
} sr_action_record_t;

struct sr_net_record{
	SR_U16						rulenum;						/* rule number */
	SR_U32						src_addr;						/* source IPv4 address */
	SR_U32						dst_addr;						/* destination IPv4 address */
	SR_U32  					src_netmask;					/* source IPv4 netmask */
	SR_U32  					dst_netmask;					/* destination IPv4 netmask */
	SR_U32  					src_port;						/* source port */
	SR_U32  					dst_port;						/* destination port */
	SR_8						proto;							/* protocol */
	SR_32						uid;							/* user id */
	char 		*process;
};

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
