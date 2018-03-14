#ifndef SR_CONFIG_H
#define SR_CONFIG_H

#include "sr_actions_common.h"
#include "sr_sal_common.h"

#define MAX_PATH_LEN	4096

enum sr_header_type{
	CONFIG_NET_RULE = 1,
	CONFIG_FILE_RULE,
	CONFIG_CAN_RULE,
	CONFIG_PHONE_ENTRY,
	CONFIG_EMAIL_ENTRY,
	CONFIG_LOG_TARGET,
	CONFIG_TYPE_MAX,
};

struct sr_config_actions{
	SR_U16 						actions_bitmap;					/* bitmap of actions */
	SR_U16 						skip_rulenum; 					/* for skip action */
	SR_U8 						log_target; 					/* syslog facility etc for log action */
	SR_U8 						email_id;   					/* store an index to a list of email addresses */
	SR_U8 						phone_id;   					/* store an index to a list of phone numbers for sms actions */
};

struct sr_net_record{
	SR_U16						rulenum;						/* rule number */
	SR_U32						src_addr;						/* source IPv4 address */
	SR_U32						dst_addr;						/* destination IPv4 address */
	SR_U32  					src_netmask;					/* source IPv4 netmask */
	SR_U32  					dst_netmask;					/* destination IPv4 netmask */
	SR_U32  					src_port;						/* source port */
	SR_U32  					dst_port;						/* destination port */
	SR_8						proto;							/* protocol */
	struct sr_config_actions	action;							/* bitmap of actions */
	SR_U16						rate_action;					/* bitmap of rate exceed actions */
	SR_U32 						max_rate;						/* maximum rate */
	SR_32						uid;							/* user id */
	SR_U16						process_size;					/* process name size in bytes */
	SR_8*						process;						/* process name */
};

struct sr_net_entry{		
	SR_U16						rulenum;						/* rule number */
	SR_U32						src_addr;						/* source IPv4 address */
	SR_U32						dst_addr;						/* destination IPv4 address */
	SR_U32  					src_netmask;					/* source IPv4 netmask */
	SR_U32  					dst_netmask;					/* destination IPv4 netmask */
	SR_U32  					src_port;						/* source port */
	SR_U32  					dst_port;						/* destination port */
	SR_8						proto;							/* protocol */
	struct sr_config_actions	action;							/* bitmap of actions */
	SR_U16						rate_action;					/* bitmap of rate exceed actions */
	SR_U32 						max_rate;						/* maximum rate */
	SR_32						uid;							/* user id */
	SR_U16						process_size;					/* process name size in bytes */
	SR_8						process[MAX_PATH_LEN];			/* process name */
};
		
struct sr_file_record{
	SR_U16						rulenum;						/* rule number */
	struct sr_config_actions	action;							/* bitmap of actions */
	SR_U16						rate_action;					/* bitmap of rate exceed actions */
	SR_U32 						max_rate;						/* maximum rate */
	SR_32						uid;							/* user id */
	SR_U16						process_size;					/* process name size in bytes */
	SR_U16						filename_size;					/* filename size in bytes */
	SR_8*						process;						/* process name */
	/* next feild should be calculated according to the real size of process feild */
#if 0
	SR_8*	  					filename;						/* filename/path. max path is 4096 on unix systems */
#endif
};

struct sr_file_entry{
	SR_U16						rulenum;						/* rule number */
	struct sr_config_actions	action;							/* bitmap of actions */
	SR_U16						rate_action;					/* bitmap of rate exceed actions */
	SR_U32 						max_rate;						/* maximum rate */
	SR_32						uid;							/* user id */
	SR_U16						process_size;					/* process name size in bytes */
	SR_U16						filename_size;					/* filename size in bytes */
	SR_8						process[MAX_PATH_LEN];			/* process name */
	SR_8	  					filename[MAX_PATH_LEN];			/* filename/path. max path is 4096 on unix systems */
};

struct sr_can_record{		
	SR_U16						rulenum;						/* rule number */
	SR_U32						msg_id;							/* can msg id */
	SR_8						direction;							/* can inbount/outbound */
	struct sr_config_actions	action;							/* bitmap of actions */
	SR_U16						rate_action;					/* bitmap of rate exceed actions */
	SR_U32 						max_rate;						/* maximum rate */
	SR_32						uid;							/* user id */
	SR_U16						process_size;					/* process name size in bytes */
	SR_8*						process;						/* process name */
};

struct sr_can_entry{		
	SR_U16						rulenum;						/* rule number */
	SR_U32						msg_id;							/* can msg id */
	SR_8						direction;							/* can inbount/outbound */
	struct sr_config_actions	action;							/* bitmap of actions */
	SR_U16						rate_action;					/* bitmap of rate exceed actions */
	SR_U32 						max_rate;						/* maximum rate */
	SR_32						uid;							/* user id */
	SR_U16						process_size;					/* process name size in bytes */
	SR_8						process[MAX_PATH_LEN];			/* process name */
};

struct sr_phone_record{
	SR_U8						phone_id;						/* phone index */
	SR_8						phone_number[15];				/* phone number */
};			
			
struct sr_email_record{			
	SR_U8						email_id;						/* email index */
	SR_U8						email_size;						/* email string length */
	SR_8*						email;							/* email address. according to IETF the max length is 254 bytes */
};

struct sr_email_entry{			
	SR_U8						email_id;						/* email index */
	SR_U8						email_size;						/* email string length */
	SR_8						email[256];						/* email address. according to IETF the max length is 254 bytes */
};
			
struct sr_log_record{			
	SR_U8						log_id;							/* log index */
	SR_U8						log_size;						/* log daemon target length */
	SR_8*						log_target;						/* log daemon target */
};

struct sr_log_entry{			
	SR_U8						log_id;							/* log index */
	SR_U8						log_size;						/* log daemon target length */
	SR_8						log_target[256];				/* log daemon target */
};

SR_BOOL config_ut(void);
SR_BOOL write_config_record (void* ptr, enum sr_header_type rec_type);
SR_BOOL read_config_file (void);
SR_BOOL read_config_db (void);
void start_cli(void);
SR_32 sr_create_filter_paths(void);
void sr_config_vsentry_db_cb(int type, int op, void *entry);

#endif /* SR_CONFIG_H */
