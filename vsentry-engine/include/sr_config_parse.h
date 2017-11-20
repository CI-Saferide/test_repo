#ifndef SR_CONFIG_PARSE_H
#define SR_CONFIG_PARSE_H

#include "sr_types.h"

struct config_params_t {
	/* vin paramas */
	SR_8 	vin[32];
	
	/* can params */
	SR_U8 	num_of_can_interface;
	SR_8 	can0_interface[10];
	SR_8 	can1_interface[10];
	SR_8 	can2_interface[10];
	SR_8 	can3_interface[10];
	SR_8 	can4_interface[10];
	
	/* collector params */
	SR_BOOL collector_enable;
	SR_U16	collector_file_size;		/* size of each log file, in mega bytes */
	SR_U16	disk_space_treshold;		/* reserved disk space in MB, before stop recording */
	SR_8	log_path[100];				/* path to completed log files, ready to upload */
	SR_8	temp_log_path[100];			/* temp folder to create intemidiate log files */
};

SR_8 read_vsentry_config(char* config_filename, struct config_params_t config);

#endif /* SR_CONFIG_PARSE_H */
