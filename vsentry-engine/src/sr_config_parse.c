#include <stdio.h>
#include <string.h>
#include "sr_config_parse.h"
#include "sr_sal_common.h"

static struct config_params_t config_params;

struct config_params_t *sr_config_get_param(void)
{
		return &config_params;
}

void config_defaults(void)
{
	strcpy(config_params.vin, "NA");
	config_params.collector_enable = SR_TRUE;
	config_params.collector_file_size = 30; /* in MB */
	config_params.disk_space_treshold = 5; /* 5% */
	strcpy(config_params.log_path, "/candata/");
	strcpy(config_params.temp_log_path, "/tmp/");
	
	config_params.cef_file_size = 1; /* in MB */
	config_params.cef_file_cycling = 10; /*amount of cef files*/
	strcpy(config_params.CEF_log_path, "/var/log/");
	config_params.cef_max_rate = (SR_U8)2;
	config_params.log_type = LOG_TYPE_SYSLOG;
	
	config_params.default_file_action = SR_CLS_ACTION_ALLOW;
	config_params.default_net_action  = SR_CLS_ACTION_ALLOW;
	config_params.default_can_action  = SR_CLS_ACTION_ALLOW;
	strcpy(config_params.vsentry_config_file, "vsentry_config_file");

	config_params.remote_server_support_enable = SR_FALSE;
	config_params.policy_update_enable = SR_FALSE;

#ifdef CONFIG_SYSTEM_POLICER
	config_params.system_policer_interval = 1;
	config_params.system_policer_threshold_percent = 5;
#endif
}

SR_32 read_vsentry_config(char* config_filename)
{
    FILE 			*fp;
    SR_8 			buf[CONFIG_LINE_BUFFER_SIZE];
    char			*position;
    SR_8 			*n __attribute__((unused));
    char            *param, *value;

    config_defaults();
    if ((fp=fopen(config_filename, "r")) == NULL) {
        CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to open config file %s, using defaults",REASON,
			config_filename);
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
        position = strstr(buf, "COLLECT_ENABLE ");
        if (position) {	
            config_params.collector_enable = (SR_BOOL)atoi(position + (strlen("COLLECT_ENABLE ")));
        }
        position = strstr(buf, "COLLECT_FILE_SIZE_MB ");
        if (position) {	
            config_params.collector_file_size = (SR_U16)atoi(position + (strlen("COLLECT_FILE_SIZE_MB ")));
        }
        position = strstr(buf, "DISK_SPACE_TRESHOLD_PERCENT ");
        if (position) {	
            config_params.disk_space_treshold = (SR_U16)atoi(position + (strlen("DISK_SPACE_TRESHOLD_PERCENT ")));
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
            config_params.cef_file_cycling = (SR_U16)atoi(position + (strlen("CEF_CYCLING ")));
        }
        position = strstr(buf, "CEF_FILE_LOG_SIZE_MB ");
        if (position) {	
            config_params.cef_file_size = (SR_U16)atoi(position + (strlen("CEF_FILE_LOG_SIZE_MB ")));
        }
		position = strstr(buf, "CEF_PATH_TEMP ");
        if (position) {	
            strcpy(config_params.CEF_log_path, position + (strlen("CEF_PATH_TEMP ")));
            config_params.CEF_log_path[strlen(config_params.CEF_log_path)-1]='\0';
        }
        position = strstr(buf, "CEF_MAX_RATE ");
        if (position) {
            config_params.cef_max_rate = (SR_U8)atoi(position + (strlen("CEF_MAX_RATE ")));
        }
        
		param = strtok(buf, " ");
		if (!param)
			continue;
		value = strtok(NULL, " \n");
		if (!value)
			continue;
		if (!strcmp(param, "LOG_TYPE_CURL"))
			config_params.log_type |= LOG_TYPE_CURL;
		if (!strcmp(param, "LOG_TYPE_SYSLOG"))
			config_params.log_type |= LOG_TYPE_SYSLOG;

		if (!strcmp(param, "DEFAULT_FILE_RULE")) {
			if (!memcmp(value, "ALLOW", strlen("ALLOW")))
				config_params.default_file_action = SR_CLS_ACTION_ALLOW;
			if (!memcmp(value, "DROP", strlen("DROP")))
				config_params.default_file_action = SR_CLS_ACTION_DROP;
			if (!memcmp(value, "ALLOW-LOG", strlen("ALLOW-LOG"))){
				config_params.default_file_action = SR_CLS_ACTION_ALLOW;
				config_params.default_file_action |= SR_CLS_ACTION_LOG;
			}
			if (!memcmp(value, "DROP-LOG", strlen("DROP-LOG"))){
				config_params.default_file_action = SR_CLS_ACTION_DROP;
				config_params.default_file_action |= SR_CLS_ACTION_LOG;
			}
		}

		if (!strcmp(param, "DEFAULT_CAN_RULE")) {
			if (!memcmp(value, "ALLOW", strlen("ALLOW")))
				config_params.default_can_action = SR_CLS_ACTION_ALLOW;
			if (!memcmp(value, "DROP", strlen("DROP")))
				config_params.default_can_action = SR_CLS_ACTION_DROP;
			if (!memcmp(value, "ALLOW-LOG", strlen("DROP-LOG"))){
				config_params.default_can_action = SR_CLS_ACTION_ALLOW;
				config_params.default_can_action |= SR_CLS_ACTION_LOG;
			}
			if (!memcmp(value, "DROP-LOG", strlen("DROP-LOG"))){
				config_params.default_can_action = SR_CLS_ACTION_DROP;
				config_params.default_can_action |= SR_CLS_ACTION_LOG;
			}
		}

		if (!strcmp(param, "DEFAULT_NET_RULE")) {
			if (!memcmp(value, "ALLOW", strlen("ALLOW")))
				config_params.default_net_action = SR_CLS_ACTION_ALLOW;
			if (!memcmp(value, "DROP", strlen("DROP")))
				config_params.default_net_action = SR_CLS_ACTION_DROP;
			if (!memcmp(value, "ALLOW-LOG", strlen("ALLOW-LOG"))){
				config_params.default_net_action = SR_CLS_ACTION_ALLOW;
				config_params.default_net_action |= SR_CLS_ACTION_LOG;
			}
			if (!memcmp(value, "DROP-LOG", strlen("DROP-LOG"))){
				config_params.default_net_action = SR_CLS_ACTION_DROP;
				config_params.default_net_action |= SR_CLS_ACTION_LOG;
			}
		}
		if (!strcmp(param, "FILE_CLS_MEM_OPTIMIZE")) {
			config_params.file_cls_mem_optimize = atoi(value);
		}
		if (!strcmp(param, "VSENTRY_CONFIG_FILE")) {
			strncpy(config_params.vsentry_config_file, value, sizeof(config_params.vsentry_config_file));
		}
		if (!strcmp(param, "REMOTE_SERVER_SUPPORT_ENABLE")) {
			config_params.remote_server_support_enable = (SR_BOOL)atoi(value);
		}
		if (!strcmp(param, "POLICY_UPDATE_ENABLE")) {
			config_params.policy_update_enable = (SR_BOOL)atoi(value);
		}

#ifdef CONFIG_SYSTEM_POLICER
		if (!strcmp(param, "SYSTEM_POLICER_INTERVAL")) {
			config_params.system_policer_interval = atoi(value);
		}
		if (!strcmp(param, "SYSTEM_POLICER_THRESHOLD_PERCENT")) {
			config_params.system_policer_threshold_percent = atoi(value);
		}
#endif
	if (!strcmp(param, "LOG_UPLOADER_URL")) {
		strncpy(config_params.log_uploader_url, value, URL_MAX_SIZE);
	}
	if (!strcmp(param, "CAN_COLLECTOR_URL")) {
		strncpy(config_params.can_collector_url, value, URL_MAX_SIZE);
	}
	if (!strcmp(param, "ML_CAN_URL")) {
		strncpy(config_params.ml_can_url, value, URL_MAX_SIZE);
	}
	if (!strcmp(param, "SR_COMMANDS_URL")) {
		strncpy(config_params.sr_commands_url, value, URL_MAX_SIZE);
	}
	if (!strcmp(param, "DYNAMIC_POLICY_URL")) {
		strncpy(config_params.dynamic_policy_url, value, URL_MAX_SIZE);
	}
	if (!strcmp(param, "STATIC_POLICY_URL")) {
		strncpy(config_params.static_policy_url, value, URL_MAX_SIZE);
	}
    }
    fclose(fp);
    CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
			"%s=configuration file succesfully loaded from %s",MESSAGE,
			config_filename);
    return SR_SUCCESS;
}
