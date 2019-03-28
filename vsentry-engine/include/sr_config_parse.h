#ifndef SR_CONFIG_PARSE_H
#define SR_CONFIG_PARSE_H

#include "sr_types.h"
#include "sr_actions_common.h"

#define PATH_BUFF 128
#define URL_MAX_SIZE 	256
#define CAN_NAME 	16
#define LOG_TYPE_CURL (1 << 0)
#define LOG_TYPE_SYSLOG (1 << 1)

#define CONFIG_LINE_BUFFER_SIZE 100 

struct config_params_t {
	/* vin paramas */
	SR_8 	vin[32];
	
	/* collector params */
	SR_BOOL collector_enable;
	SR_U16	collector_file_size;				/* size of each log file, in mega bytes */
	SR_U16	disk_space_treshold;				/* reserved disk space in MB, before stop recording */
	SR_8	log_path[PATH_BUFF];				/* path to completed log files, ready to upload */
	SR_8	temp_log_path[PATH_BUFF];			/* temp folder to create intemidiate log files */
	
	SR_U16	cef_file_size;						/* size of each cef log file, in megabytes */
	SR_U16	cef_file_cycling;					/* amount of files that cycle */
	SR_8	CEF_log_path[PATH_BUFF];			/* folder to create cef files */
	
	/* config params */
	SR_U8	cef_max_rate;						/* max allowed cef message rate per second for classifier and ml algorithms */	
	SR_U8   log_type;
	SR_U16	default_file_action;
	SR_U16  default_net_action;
	SR_U16	default_can_action;

	SR_U8	file_cls_mem_optimize;
	SR_8	vsentry_config_file[PATH_BUFF];

	SR_BOOL	remote_server_support_enable;
	SR_BOOL	policy_update_enable;

#ifdef CONFIG_SYSTEM_POLICER 
	SR_U8	system_policer_interval;
	SR_U8	system_policer_threshold_percent;
#endif
	SR_8	log_uploader_url[URL_MAX_SIZE];
	SR_8	can_collector_url[URL_MAX_SIZE];
	SR_8	dynamic_policy_url[URL_MAX_SIZE];
	SR_8	ml_can_url[URL_MAX_SIZE];
	SR_8	sr_commands_url[URL_MAX_SIZE];
	SR_8	static_policy_url[URL_MAX_SIZE];
	SR_8	policy_dir[PATH_BUFF];
};

SR_32 read_vsentry_config(char* config_filename);

struct config_params_t *sr_config_get_param(void);

#endif /* SR_CONFIG_PARSE_H */
