/* sr_config.c */
#include "sr_sal_common.h"
#include "sr_static_policy.h"
#include "sr_tasks.h"
#include "sr_curl.h"
#include <ctype.h>
#include "sr_config_parse.h"
#include "sr_command.h"
#include "sysrepo_mng.h"

static SR_BOOL is_run_db_mng = SR_TRUE;
static SR_U32 static_policy_version;
extern struct config_params_t config_params;

#define STATIC_POLICY_URL "http://saferide-policies.eu-west-1.elasticbeanstalk.com/policy/static/sync"
#define STATIC_POLICY_VERSION_FILE "/etc/sentry/version"
#define STATIC_POLICY_CPU_FILE "/etc/sentry/cpu_info.txt"
#define STATIC_POLICY_IP_VERSION "X-IP-VERSION"
#define STATIC_POLICY_SYSTEM_VERSION "X-SYSTEM-VERSION"
#define STATIC_POLICY_CAN_VERSION "X-CAN-VERSION"
#define STATIC_POLICY_ACTIONS_VERSION "X-ACTIONS-VERSION"
#define STATIC_POLICY_VERSION_SIZE 100

static SR_32 set_version_to_file(SR_U32 version)
{
	FILE *fout;

	if (!(fout = fopen(STATIC_POLICY_VERSION_FILE, "w"))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"failed openning file :%s", STATIC_POLICY_VERSION_FILE);
                return SR_ERROR;
	}
	fprintf(fout, "%u", version);

	fclose(fout);

	return SR_SUCCESS;
}

static SR_32 get_vesrion_from_file(SR_U32 *version)
{
	FILE *fin;

	*version = 0;
	if (!(fin = fopen(STATIC_POLICY_VERSION_FILE, "r")))
                return set_version_to_file(0);
	if (fscanf(fin, "%u", version) < 1)
                set_version_to_file(0);

	fclose(fin);

	return SR_SUCCESS;
}

static SR_32 get_server_db(sysrepo_mng_handler_t *handler)
{
	CURL *curl;
	CURLcode res;
	struct curl_slist *chunk = NULL;
	char ip_version[STATIC_POLICY_VERSION_SIZE], system_version[STATIC_POLICY_VERSION_SIZE], can_version[STATIC_POLICY_VERSION_SIZE], action_version[STATIC_POLICY_VERSION_SIZE];
	SR_U32 new_version = 0;
 	struct curl_httppost* post = NULL, *last = NULL; 
	struct curl_fetch_st curl_fetch = {};
	struct curl_fetch_st *fetch = &curl_fetch;
	char post_buf[64];
	char state_name[32];
	char host_info[512];

	sal_get_host_info(host_info, 512);

	SR_CURL_INIT(STATIC_POLICY_URL);
	
	fetch->payload = NULL;
	fetch->size = 0;

	sprintf(ip_version, "%s: %u", STATIC_POLICY_IP_VERSION, static_policy_version);
	sprintf(system_version, "%s: %u", STATIC_POLICY_SYSTEM_VERSION, static_policy_version);
	sprintf(can_version, "%s: %u", STATIC_POLICY_CAN_VERSION, static_policy_version);
	sprintf(action_version, "%s: %u", STATIC_POLICY_ACTIONS_VERSION, static_policy_version);
	curl_formadd(&post, &last, CURLFORM_COPYNAME, "cpu", CURLFORM_BUFFER, STATIC_POLICY_CPU_FILE, CURLFORM_BUFFERPTR,
		host_info, CURLFORM_BUFFERLENGTH, strlen(host_info), CURLFORM_END);
	curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
	//curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	snprintf(post_buf, 64, "X-VIN: %s", config_params.vin);
	chunk = curl_slist_append(chunk, post_buf);
	sr_command_get_state_str(state_name, 32);
	snprintf(post_buf, 64, "X-STATE: %s", state_name);
	chunk = curl_slist_append(chunk,  post_buf);
	sr_command_get_ml_state_str(state_name, 32);
	snprintf(post_buf, 64, "X-STATE-ML: %s", state_name);
	chunk = curl_slist_append(chunk,  post_buf);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
	chunk = curl_slist_append(chunk, ip_version);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
	chunk = curl_slist_append(chunk, can_version);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
	chunk = curl_slist_append(chunk, system_version);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
	chunk = curl_slist_append(chunk, action_version);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) fetch);
    
	/* Perform the request, res will get the return code */
	if ((res = curl_easy_perform(curl)) != CURLE_OK) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,  "curl_easy_perform failed: %s", curl_easy_strerror(res));
		goto out;
	}

#ifdef SR_STATIC_POLICY_DEBUG
	printf("Fetched payload :%s: \n", fetch->payload);
#endif
	if (!fetch->payload)	
		goto out;
	sysrepo_mng_parse_json(handler, fetch->payload, &new_version, static_policy_version);
	if (new_version != static_policy_version) {
		static_policy_version = new_version;
		if (set_version_to_file(new_version) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,  "FAILED setting new version");
		}
	}

out:
	if (chunk)
                curl_slist_free_all(chunk);
	SR_CURL_DEINIT(curl);
	if (fetch->payload)
		free(fetch->payload);

	return SR_SUCCESS;
}

SR_32 database_management(void *p)
{
	sysrepo_mng_handler_t handler;

    	if (sysrepo_mng_session_start(&handler)) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,  "sysrepo_mng_session_start failed \n");
        	goto cleanup;
    	}

	while (is_run_db_mng) { 
		if (get_server_db(&handler) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,  "get_server_db_failed:");
		}
		sleep(1);
	}

cleanup:
	sysrepo_mng_session_end(&handler);
	return SR_SUCCESS;
}

SR_32 sr_static_policy_db_mng_start(void)
{
	if (get_vesrion_from_file(&static_policy_version) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "failed to get version");
		return SR_ERROR;
	}

	is_run_db_mng = SR_TRUE;
	if (sr_start_task(SR_STATIC_POLICY, database_management) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "failed to start static policy");
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

void sr_static_policy_db_mng_stop(void)
{
	is_run_db_mng = SR_FALSE;

	sr_stop_task(SR_STATIC_POLICY);
}
