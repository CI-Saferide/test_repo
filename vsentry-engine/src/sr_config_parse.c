#include <stdio.h>
#include <string.h>
#include "sr_config_parse.h"
#include "sr_sal_common.h"

struct config_params_t config_params;

void config_defaults(void)
{
	strcpy(config_params.vin, "NA");
	config_params.num_of_can_interface = 1;
	strcpy(config_params.can0_interface, DEFAULT_CAN0_INTERFACE);
	strcpy(config_params.can1_interface, DEFAULT_CAN1_INTERFACE);
	strcpy(config_params.can2_interface, DEFAULT_CAN2_INTERFACE);
	strcpy(config_params.can3_interface, DEFAULT_CAN3_INTERFACE);
	strcpy(config_params.can4_interface, DEFAULT_CAN4_INTERFACE);
	config_params.collector_enable = SR_TRUE;
	config_params.collector_file_size = 30; /* in MB */
	config_params.disk_space_treshold = 5; /* 5% */
	strcpy(config_params.log_path, "/candata/");
	strcpy(config_params.temp_log_path, "/tmp/");
	
	config_params.cef_file_size = 1; /* in MB */
	config_params.cef_file_cycling = 4; /*amount of cef files*/
	strcpy(config_params.CEF_log_path, "/var/log/");
}

#define CONFIG_LINE_BUFFER_SIZE 100

SR_8 read_vsentry_config(char* config_filename, struct config_params_t config) 
{
    FILE 	*fp;
    SR_8 	buf[CONFIG_LINE_BUFFER_SIZE];
    SR_8	*position;
    SR_8 	*n __attribute__((unused));

    if ((fp=fopen(config_filename, "r")) == NULL) {
        CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"Failed to open config file %s, using defaults\n", config_filename);
        return SR_ERROR;
    }
    while(! feof(fp)) {
        n = fgets(buf, CONFIG_LINE_BUFFER_SIZE, fp);
        if (buf[0] == '#' || strlen(buf) < 4) {
            continue;
        }
        position = strstr(buf, "VIN ");
        if (position) {	
            strcpy(config_params.vin, position + (strlen("VIN ")));
            config_params.vin[strlen(config_params.vin)-1]='\0';
        }
        position = strstr(buf, "NUM_OF_CAN_IF ");
        if (position) {	
            config_params.num_of_can_interface =  atoi(position + (strlen("NUM_OF_CAN_IF ")));
        }
        position = strstr(buf, "CAN0_IF ");
        if (position) {	
            strcpy(config_params.can0_interface, position + (strlen("CAN0_IF ")));
            config_params.can0_interface[strlen(config_params.can0_interface)-1]='\0';
        }
        position = strstr(buf, "CAN1_IF ");
        if (position) {	
            strcpy(config_params.can1_interface, position + (strlen("CAN1_IF ")));
            config_params.can1_interface[strlen(config_params.can1_interface)-1]='\0';
        }
        position = strstr(buf, "CAN2_IF ");
        if (position) {	
            strcpy(config_params.can2_interface, position + (strlen("CAN2_IF ")));
            config_params.can2_interface[strlen(config_params.can2_interface)-1]='\0';
        }
        position = strstr(buf, "CAN3_IF ");
        if (position) {	
            strcpy(config_params.can3_interface, position + (strlen("CAN3_IF ")));
            config_params.can3_interface[strlen(config_params.can3_interface)-1]='\0';
        }
        position = strstr(buf, "CAN4_IF ");
        if (position) {	
            strcpy(config_params.can4_interface, position + (strlen("CAN4_IF ")));
            config_params.can4_interface[strlen(config_params.can4_interface)-1]='\0';
        }
        position = strstr(buf, "COLLECT_ENABLE ");
        if (position) {	
            config_params.collector_enable =  atoi(position + (strlen("COLLECT_ENABLE ")));
        }
        position = strstr(buf, "COLLECT_FILE_SIZE_MB ");
        if (position) {	
            config_params.collector_file_size =  atoi(position + (strlen("COLLECT_FILE_SIZE_MB ")));
        }
        position = strstr(buf, "DISK_SPACE_TRESHOLD_PERCENT ");
        if (position) {	
            config_params.disk_space_treshold =  atoi(position + (strlen("DISK_SPACE_TRESHOLD_PERCENT ")));
        }
        position = strstr(buf, "LOG_PATH ");
        if (position) {	
            strcpy(config_params.log_path, position + (strlen("LOG_PATH ")));
            config_params.log_path[strlen(config_params.log_path)-1]='\0';
        }
        position = strstr(buf, "LOG_PATH_TEMP ");
        if (position) {	
            strcpy(config_params.temp_log_path, position + (strlen("LOG_PATH_TEMP ")));
            config_params.temp_log_path[strlen(config_params.temp_log_path)-1]='\0';
        }
        
       position = strstr(buf, "CEF_CYCLING ");
        if (position) {	
            config_params.cef_file_cycling =  atoi(position + (strlen("CEF_CYCLING ")));
        }
        position = strstr(buf, "CEF_FILE_LOG_SIZE_MB ");
        if (position) {	
            config_params.cef_file_size =  atoi(position + (strlen("CEF_FILE_LOG_SIZE_MB ")));
        }
		position = strstr(buf, "CEF_PATH_TEMP ");
        if (position) {	
            strcpy(config_params.CEF_log_path, position + (strlen("CEF_PATH_TEMP ")));
            config_params.CEF_log_path[strlen(config_params.CEF_log_path)-1]='\0';
        }
    }
    fclose(fp);
    return SR_SUCCESS;
}
