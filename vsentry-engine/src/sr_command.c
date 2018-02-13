/* sr_config.c */
#include "sr_msg_dispatch.h"
#include "sr_tasks.h"
#include "sr_curl.h"
#include <ctype.h>
#include "sr_stat_analysis.h"
#include "sr_control.h"
#include "sr_config_parse.h"
#ifdef CONFIG_CAN_ML
#include "sr_ml_can.h"
#endif /* __SR_ML_CAN__ */

static SR_BOOL is_run_cmd  = SR_TRUE;

#define GET_CMD_URL "http://saferide-policies.eu-west-1.elasticbeanstalk.com/commands/sync"
#define CMD_LEARN "StateLearn"
#define CMD_OFF "StateOff"
#define CMD_PROTECT "StateProtect"
#define CMD_ENABLE "ProtectEnabled"
#define CMD_DISABLE "ProtectDisabled"

static SR_BOOL last_is_enabled = SR_TRUE;

static SR_32 handle_engine_start_stop(SR_BOOL is_on)
{
    FILE *f;

    usleep(500000);
	sr_control_set_state(is_on);
    if (!(f = fopen("/tmp/sec_state", "w"))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,  "failed opening file /tmp/sec_state");
		return SR_ERROR;
	}
		
	fprintf(f, is_on ? "on" : "off");
   	fclose(f);

	return SR_SUCCESS;
}

void sr_command_get_ml_state_str(char *state, SR_U32 size)
{
	switch (sr_stat_analysis_learn_mode_get()) {
		case SR_STAT_MODE_LEARN:
			strncpy(state, CMD_LEARN, size);
			break;
		case SR_STAT_MODE_PROTECT:
			strncpy(state, CMD_PROTECT, size);
			break;
		case SR_STAT_MODE_OFF:
			strncpy(state, CMD_OFF, size);
			break;
		default:
			strncpy(state, "ERROR", size);
			break;
	}
}

void sr_command_get_state_str(char *state, SR_U32 size)
{
	if (last_is_enabled)
		strncpy(state, CMD_ENABLE, size);
	else 
		strncpy(state, CMD_DISABLE, size);
}

static SR_32 handle_command(void)
{
	CURL *curl;
	CURLcode res;
	struct curl_slist *chunk = NULL;
	char post_buf[64];
	struct config_params_t *config_params;

	struct curl_fetch_st curl_fetch;
	struct curl_fetch_st *fetch = &curl_fetch;

	config_params = sr_config_get_param();

	SR_CURL_INIT(GET_CMD_URL);
	curl_easy_setopt(curl, CURLOPT_URL, GET_CMD_URL);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);

	fetch->payload = (char *) calloc(1, sizeof(fetch->payload));
	fetch->size = 0;

	//curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	snprintf(post_buf, 64, "X-VIN: %s", config_params->vin);
	chunk = curl_slist_append(chunk,  post_buf);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) fetch);

	res = curl_easy_perform(curl);
	if(res != CURLE_OK) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,  "curl_easy_perform failed: %s", curl_easy_strerror(res));
		goto out;
	}
        if (!fetch->payload)
		goto out;

	if (strstr(fetch->payload, CMD_LEARN)) {
		sr_stat_analysis_learn_mode_set(SR_STAT_MODE_LEARN);
		ml_can_set_state(SR_ML_CAN_MODE_LEARN);
		CEF_log_event(SR_CEF_CID_SYSTEM, "state change", SEVERITY_LOW,
							"state changed to learning mode");
	}
	if (strstr(fetch->payload, CMD_PROTECT)) {
		sr_stat_analysis_learn_mode_set(SR_STAT_MODE_PROTECT);
		ml_can_set_state(SR_ML_CAN_MODE_PROTECT);
		CEF_log_event(SR_CEF_CID_SYSTEM, "state change", SEVERITY_LOW,
							"state changed to protecting mode");
	}
	if (strstr(fetch->payload, CMD_OFF)) {
		sr_stat_analysis_learn_mode_set(SR_STAT_MODE_OFF);
		ml_can_set_state(SR_ML_CAN_MODE_HALT);
		CEF_log_event(SR_CEF_CID_SYSTEM, "state change", SEVERITY_LOW,
							"state changed to OFF mode");
	}
	if (strstr(fetch->payload, CMD_ENABLE)) {
		handle_engine_start_stop(SR_TRUE);
		last_is_enabled = SR_TRUE;
		CEF_log_event(SR_CEF_CID_SYSTEM, "state change", SEVERITY_LOW,
							"state changed to engine enabled");
	}
	if (strstr(fetch->payload, CMD_DISABLE)) {
		handle_engine_start_stop(SR_FALSE);
		last_is_enabled = SR_FALSE;
		CEF_log_event(SR_CEF_CID_SYSTEM, "state change", SEVERITY_LOW,
							"state changed to engine diabled");
	}

out:
	if (chunk)
		curl_slist_free_all(chunk);
	SR_CURL_DEINIT(curl);
        if (fetch->payload)
                free(fetch->payload);

	return SR_SUCCESS;
}

SR_32 command_management(void *p)
{
	while (is_run_cmd) { 
		if (handle_command() != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,  "handle_commands:");
		}
		sleep(1);
	}

	return SR_SUCCESS;
}

SR_32 sr_get_command_start(void)
{
	is_run_cmd = SR_TRUE;
	if (sr_start_task(SR_GET_COMMAND, command_management) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "failed to start get command");
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

void sr_get_command_stop(void)
{
	is_run_cmd = SR_FALSE;

	sr_stop_task(SR_GET_COMMAND);
}
