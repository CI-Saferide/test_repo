#ifndef SR_CONFIG_PARSE_H
#define SR_CONFIG_PARSE_H

#include "sr_types.h"

#define PATH_BUFF 	128
#define CAN_NAME 	16
#define LOG_TYPE_CURL (1 << 0)
#define LOG_TYPE_SYSLOG (1 << 1)


struct config_params_t {
	/* vin paramas */
	SR_8 	vin[32];
	
	/* can params */
	SR_U8 	num_of_can_interface;
	SR_8 	can0_interface[CAN_NAME];
	SR_8 	can1_interface[CAN_NAME];
	SR_8 	can2_interface[CAN_NAME];
	SR_8 	can3_interface[CAN_NAME];
	SR_8 	can4_interface[CAN_NAME];
	
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
	
};

SR_32 read_vsentry_config(char* config_filename);

struct config_params_t *sr_config_get_param(void);

#endif /* SR_CONFIG_PARSE_H */
