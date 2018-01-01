/* sr_config.c */
#include "sr_config.h"
#include "sr_sal_common.h"
#include "sr_cls_network_common.h"
#include "sr_cls_port_control.h"
#include "sr_cls_network_control.h"
#include "sr_cls_rules_control.h"
#include "sr_cls_canbus_control.h"
#include "sr_cls_file_control.h"
#include "sr_msg.h"
#include "sr_msg_dispatch.h"
#include "sr_control.h"
#include "sentry.h"
#include "action.h"
#include "ip_rule.h"
#include "file_rule.h"
#include "can_rule.h"
#include "sr_db.h"
#include "jsmn.h"
#include <sysrepo.h>
#include "sr_static_policy.h"
#include "sr_tasks.h"
#include "sr_curl.h"
#include <ctype.h>
#include "sr_config_parse.h"

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

#define ACT_PREFIX   "/saferide:config/sr_actions/list_actions["
#define CAN_PREFIX   "/saferide:config/net/can/rule["
#define IP_PREFIX    "/saferide:config/net/ip/rule["
#define FILE_PREFIX  "/saferide:config/system/file/rule["
#define IP "ip"
#define NET "net"
#define RULE "rule"
#define TUPLE "tuple"
#define JSON_TRUE "true"
#define JSON_PRIORITY "priority"
#define JSON_SRCIP "srcIp"
#define JSON_DSTIP "dstIp"
#define JSON_SRCNETMASK "srcNetmask"
#define JSON_DSTNETMASK "dstNetmask"
#define JSON_PROTOCOL "protocol"
#define JSON_SRCPORT "srcPort"
#define JSON_DSTPORT "dstPort"
#define JSON_PROGRAM "execProgram"
#define JSON_USER "user"
#define ACTION_VER "actionVersion"
#define IP_VER "ipVersion"
#define CAN_VER "canVersion"
#define SYSTEM_VER "systemVersion"
#define IP_POLICIES "ipPolicies"
#define CAN_POLICIES "canPolicies"
#define SYSTEM_POLICIES "systemPolicies"
#define ACTIONS "actions"
#define DB_PREFIX "saferide:config" 
#define SR_ACTIONS "sr_actions"
#define ACTION "action"
#define LIST_ACTIONS "list_actions"
#define LOG_FACILITY "log/log_facility"
#define LOG_SEVERITY "log/log_severity"
#define BLACK_LIST "black-list"
#define TERMINATE "terminate"
#define JSON_ACTION "action"
#define JSON_ACTION_DROP "drop"
#define JSON_ACTION_ALLOW "allow"
#define JSON_ACTION_LOG "log"
#define JSON_FILE_NAME "fileName"
#define JSON_PERMISSIONS "permissions"
#define JSON_CAN_MESSAGE_ID "msgId"
#define JSON_CAN_DIRECTION "canDirection"
#define MAX_STR_SIZE 512
#define ARRAYSIZE(arr)  (sizeof(arr) / sizeof(arr[0]))

typedef struct { 
	char*       name;
	sr_type_t   type;
	void*       value;
} param_t;

enum {
	SUB_TYPE_NONE, 
	SUB_TYPE_RULE,
	SUB_TYPE_TUPLE,
	SUB_TYPE_MAX = SUB_TYPE_TUPLE,
	SUB_TYPE_TOTAL = (SUB_TYPE_MAX + 1),
};

enum {  
	TYPE_NONE,
	TYPE_ACTION,
	TYPE_FILE,
	TYPE_IP,
	TYPE_CAN,
	TYPE_MAX = TYPE_CAN,
	TYPE_TOTAL = (TYPE_MAX + 1),
};

static param_t default_action_params[] = {
    {"action", SR_STRING_T, "allow"},
    {"log/log_facility", SR_STRING_T, "syslog"},
    {"log/log_severity", SR_STRING_T, "none"},
    {"black-list", SR_BOOL_T, false},
    {"terminate", SR_BOOL_T, false}
};

static param_t default_can_tuple_params[] = {
    {"msg_id", SR_STRING_T, "000"},
    {"direction", SR_STRING_T, "out"},
    {"user", SR_STRING_T, ""},
    {"program", SR_STRING_T, ""},
    {"max_rate", SR_UINT32_T, 0}
};

static param_t default_file_tuple_params[] = {
    {"filename", SR_STRING_T, ""},
    {"permission", SR_STRING_T, "000"},
    {"user", SR_STRING_T, ""},
    {"program", SR_STRING_T, ""},
    {"max_rate", SR_UINT32_T, 0}
};

static param_t default_ip_tuple_params[] = {
    {"srcaddr", SR_STRING_T, "0.0.0.0"},
    {"srcnetmask", SR_STRING_T, "0.0.0.0"},
    {"dstaddr", SR_STRING_T, "0.0.0.0"},
    {"dstnetmask", SR_STRING_T, "0.0.0.0"},
    {"proto", SR_UINT8_T, 0},
    {"srcport", SR_UINT16_T, 0},
    {"dstport", SR_UINT16_T, 0},
    {"user", SR_STRING_T, ""},
    {"program", SR_STRING_T, ""},
    {"max_rate", SR_UINT32_T, 0}
};

static param_t default_rule_params[] = {
    {"action", SR_STRING_T, "allow"},
};

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

static int set_default_params(sr_session_ctx_t *sess, char *xpath, param_t* ptr,
    int size)
{
	int rc = SR_ERR_OK, i;
	sr_val_t value = {0};
	char param_xpath[MAX_STR_SIZE];

	for (i=0; i<size; i++) {
		/* prepare the xpath of the tuple parameter */
		snprintf(param_xpath, MAX_STR_SIZE, "%s/%s",xpath, ptr[i].name);

		/* init the value and type*/
		value.type = ptr[i].type;
		switch(value.type) {
		case SR_STRING_T:
 			value.data.string_val = (char*)ptr[i].value;
			break;
		case SR_UINT8_T:
			value.data.uint8_val = 0;
 			break;
		case SR_UINT16_T:
			value.data.uint16_val = 0;
			break;
		case SR_UINT32_T:
			value.data.uint32_val = 0;
			break;
		case SR_BOOL_T:
			value.data.bool_val = ptr[i].value;
			break;
		default:
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "ERROR this type (%d) not supported", value.type);
			rc = SR_ERR_UNSUPPORTED;
			break;
		}

		if (rc == SR_ERR_OK) {
			/* set the default value */
			rc = sr_set_item(sess, param_xpath, &value, SR_EDIT_DEFAULT);
			if (SR_ERR_OK != rc) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "ERROR sr_set_item %s: %s\n", param_xpath,
					sr_strerror(rc));
			}
		}
	}

	return rc;
}

static int set_str_value(sr_val_t *value, char* str_value)
{
    int rc = SR_ERR_OK;

    if (!value) {
        return SR_ERR_INVAL_ARG;
    }

    switch (value->type) {
    case SR_BOOL_T:
        if (strncmp(str_value, "false", strlen(str_value)) == 0)
            value->data.bool_val = false;
        else
            value->data.bool_val = true;
        break;
    case SR_INT8_T:
        value->data.int8_val = atoi(str_value);
        break;
    case SR_INT16_T:
        value->data.int16_val = atoi(str_value);
        break;
    case SR_INT32_T:
        value->data.int32_val = atoi(str_value);
        break;
    case SR_UINT8_T:
        value->data.uint8_val = atoi(str_value);
        break;
    case SR_UINT16_T:
        value->data.uint16_val = atoi(str_value);
        break;
    case SR_UINT32_T:
        value->data.uint32_val = atoi(str_value);
        break;
    case SR_STRING_T:
        value->data.string_val = str_value;
        break;
    default:
	CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "ERROR unsupported value type");
        rc = SR_ERR_UNSUPPORTED;
        break;
    }

    return rc;
}

static void get_entry_type(int *p_type, int *p_sub_type, char *entry)
{
    char *tmp;
    int len = 0;

    if (!p_type || !p_sub_type || !p_sub_type)
        return;

    /* check if this is an action/rule entry*/
    if (strncmp(entry, ACT_PREFIX, strlen(ACT_PREFIX)) == 0) {
        *p_type = TYPE_ACTION;
        return;
    } else if (strncmp(entry, CAN_PREFIX, strlen(CAN_PREFIX)) == 0) {
        *p_type = TYPE_CAN;
        *p_sub_type = SUB_TYPE_RULE;
        len = strlen(CAN_PREFIX);
    } else if (strncmp(entry, IP_PREFIX, strlen(IP_PREFIX)) == 0) {
        *p_type = TYPE_IP;
        *p_sub_type = SUB_TYPE_RULE;
        len = strlen(IP_PREFIX);
    } else if (strncmp(entry, FILE_PREFIX, strlen(FILE_PREFIX)) == 0) {
        *p_type = TYPE_FILE;
        *p_sub_type = SUB_TYPE_RULE;
        len = strlen(FILE_PREFIX);
    } else {
        /* unknown */
        return;
    }

    tmp = entry+len;
    /* check if it is a tuple */
    if (strstr(tmp, "]/tuple[id="))
        *p_sub_type = SUB_TYPE_TUPLE;
}

static SR_32 um_set_param(sr_session_ctx_t *sess, char *str_param)
{
	int type = TYPE_NONE, sub_type = SUB_TYPE_NONE, array_size = 0;
	param_t* ptr = NULL;

	get_entry_type(&type, &sub_type, str_param);
	switch (type) {
		case TYPE_ACTION:
			ptr = default_action_params;
			array_size = ARRAYSIZE(default_action_params);
			break;
		case TYPE_FILE:
 			if (sub_type == SUB_TYPE_TUPLE) {
				ptr = default_file_tuple_params;
				array_size = ARRAYSIZE(default_file_tuple_params);
			} else if (sub_type == SUB_TYPE_RULE) {
				ptr = default_rule_params;
				array_size = ARRAYSIZE(default_rule_params);
			}
			break;
		case TYPE_IP:
			if (sub_type == SUB_TYPE_TUPLE) {
				ptr = default_ip_tuple_params;
				array_size = ARRAYSIZE(default_ip_tuple_params);
			} else if (sub_type == SUB_TYPE_RULE) {
				ptr = default_rule_params;
				array_size = ARRAYSIZE(default_rule_params);
			}
			break;
		case TYPE_CAN:
			if (sub_type == SUB_TYPE_TUPLE) {
				ptr = default_can_tuple_params;
				array_size = ARRAYSIZE(default_can_tuple_params);
			} else if (sub_type == SUB_TYPE_RULE) {
				ptr = default_rule_params;
				array_size = ARRAYSIZE(default_rule_params);
			}
			break;
		default:
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "can't get type of %s", str_param);
			break;
	}

        if (ptr) {
                if (set_default_params(sess, str_param, ptr, array_size) != SR_ERR_OK) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "setting new item params to default");
			return SR_ERROR;
		}
        }

	return SR_SUCCESS;
}

static SR_32 um_set_value(sr_session_ctx_t *sess, char *str_param, char *str_value)
{
	sr_val_t *value = NULL, new_val = {0};
	int rc;

	rc = sr_get_item(sess, str_param, &value);
	if (rc != SR_ERR_OK) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, " ERROR sr_get_item %s:", str_param, sr_strerror(rc));
		return rc;
	}
	memset(&new_val, 0, sizeof(sr_val_t));
	new_val.type = value->type;
	sr_free_val(value);

	rc = set_str_value(&new_val, str_value);
	if (rc != SR_ERR_OK) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "Error set_str_value failed to set %s to %s: %s",
			str_param, str_value, sr_strerror(rc));
		return rc;
	}

	rc = sr_set_item(sess, str_param, &new_val, SR_EDIT_DEFAULT);
	if (SR_ERR_OK != rc) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "ERROR sr_set_item %s to %s: %s\n", str_param,
			str_value, sr_strerror(rc));
		return rc;
	}

	return SR_SUCCESS;
}

static SR_32 json_get_int(jsmntok_t *t,  char *buf)
{
	char token[512];

	memcpy(token, buf + t->start, t->end - t->start);
	token[t->end - t->start] = 0;
	return atoi(token);
}

static void json_get_string(jsmntok_t *t, char *buf, char *string)
{
	memcpy(string, buf + t->start, t->end - t->start);
	string[t->end - t->start] = 0;
}

static void json_get_int_string(jsmntok_t *t, char *buf, char *string)
{
	SR_32 tmp;
	tmp = json_get_int(t, buf);
	sprintf(string, "%d", tmp);
}

static void json_get_bool(jsmntok_t *t, char *buf, SR_BOOL *is_true)
{
	if (memcmp(buf + t->start, JSON_TRUE, t->end - t->start) == 0)
		*is_true = SR_TRUE;
	else
		*is_true = SR_FALSE;
}

static void handle_actions(sr_session_ctx_t *sess, char *buf, jsmntok_t *t, int *i)
{
        SR_32 a_i, a_n, f_i, f_n, rc;
	char action_name[100], str_param[MAX_STR_SIZE], str_value[MAX_STR_SIZE];
	SR_BOOL is_drop ,is_allow, is_log;

        (*i)++;
	a_n = t[*i].size;
        for (a_i = 0 ; a_i < a_n; a_i++) {
                (*i)++;
		f_n = t[*i].size;
		is_drop = is_allow = is_log = SR_FALSE;
		for (f_i = 0; f_i < f_n; f_i++) {
                	(*i)++;
                        if (jsoneq(buf, &t[*i], "id") == 0) {
                                (*i)++;
                                continue;
                        }

			if (jsoneq(buf, &t[*i], "name") == 0) {
                		(*i)++;
				json_get_string(&t[*i], buf, action_name);
				continue;
			}
			if (jsoneq(buf, &t[*i], "drop") == 0) {
                		(*i)++;
				json_get_bool(&t[*i], buf, &is_drop);
				continue;
			}
			if (jsoneq(buf, &t[*i], "allow") == 0) {
                		(*i)++;
				json_get_bool(&t[*i], buf, &is_allow);
				continue;
			}
			if (jsoneq(buf, &t[*i], "log") == 0) {
                		(*i)++;
				json_get_bool(&t[*i], buf, &is_log);
				continue;
			}
                	(*i)++;
		}
		sprintf(str_param, "/%s/%s/%s[name='%s']", DB_PREFIX, SR_ACTIONS, LIST_ACTIONS, action_name);
#ifdef JSON_DEBUG
		printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Action#%s drop:%d str_param:%s:\n", action_name, is_drop, str_param);
#endif

		rc = sr_set_item(sess, str_param, NULL, SR_EDIT_DEFAULT);
		if (SR_ERR_OK != rc) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "ERROR sr_set_item %s: %s\n", str_param, sr_strerror(rc));
                	continue;
		}

		sprintf(str_param, "/%s/%s/%s[name='%s']", DB_PREFIX, SR_ACTIONS, LIST_ACTIONS, action_name);
		rc = set_default_params(sess, str_param, default_action_params, ARRAYSIZE(default_action_params));
                if (rc != SR_ERR_OK) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "ERROR setting new item params to default");
			continue; 
		}

		strncpy(str_value, is_drop ? JSON_ACTION_DROP : JSON_ACTION_ALLOW, MAX_STR_SIZE);
		sprintf(str_param, "/%s/%s/%s[name='%s']/%s", DB_PREFIX, SR_ACTIONS, LIST_ACTIONS, action_name, ACTION);

		if (um_set_value(sess, str_param, str_value) != SR_SUCCESS)  {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "ERROR after um_set_value str_param:%s: str_value:%s: \n", str_param, str_value);
			continue;
		}

		if (!is_log)
			continue;

		sprintf(str_param, "/%s/%s/%s[name='%s']/%s", DB_PREFIX, SR_ACTIONS, LIST_ACTIONS, action_name, LOG_FACILITY);
		strcpy(str_value, "syslog");

		if (um_set_value(sess, str_param, str_value) != SR_SUCCESS) 
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "ERROR after um_set_value str_param:%s: str_value:%s: \n", str_param, str_value);
        }
}

static SR_32 create_rule(sr_session_ctx_t *sess, char *buf, jsmntok_t *t, char *prefix, SR_32 *rule_id)
{
	SR_32 id;
	char str_param[MAX_STR_SIZE];

	id = json_get_int(t, buf);
	sprintf(str_param, "%snum='%d']", prefix, id);
	if (um_set_param(sess, str_param) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "ERROR ip policies : um_set_param failed"); 
		return SR_ERROR;
	}
	sprintf(str_param, "%snum='%d']/%s[id='%d']", prefix, id, TUPLE, 0);
	if (um_set_param(sess, str_param) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "ERROR ip policies : um_set_param failed"); 
		return SR_ERROR;
	}

	*rule_id = id;

	return SR_SUCCESS;
}

static SR_32 handle_string_from_tuple(sr_session_ctx_t *sess, char *buf, jsmntok_t *t, char *prefix, SR_32 rule_id, SR_32 tuple_id, char *field_name, char *default_value)
{
	char str_param[MAX_STR_SIZE], str_value[MAX_STR_SIZE];

	*str_value = 0;
	json_get_string(t, buf, str_value);
	sprintf(str_param, "%snum='%d']/%s[id='%d']/%s", prefix, rule_id, TUPLE, tuple_id, field_name);
	if (!*str_value || !strcmp(str_value, "null")) {
		strcpy(str_value, default_value);
	}
	if (um_set_value(sess, str_param, str_value) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "ERROR after um_set_value str_param:%s: str_value:%s: \n", str_param, str_value);
		return SR_ERROR;
	}

	return SR_ERROR;
}

static SR_32 handle_string_from_rule(sr_session_ctx_t *sess, char *buf, jsmntok_t *t, char *prefix, SR_32 rule_id, char *field_name)
{
	char str_param[MAX_STR_SIZE], str_value[MAX_STR_SIZE];

	json_get_string(t, buf, str_value);
	sprintf(str_param, "%snum='%d']/%s", prefix, rule_id, field_name);
	if (um_set_value(sess, str_param, str_value) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "ERROR after um_set_value str_param:%s: str_value:%s: \n", str_param, str_value);
		return SR_ERROR;
	}

	return SR_ERROR;
}

static void handle_ip_policies(sr_session_ctx_t *sess, char *buf, jsmntok_t *t, int *i)
{
	SR_32 ip_i, ip_n, o_n, o_i, id;
	char str_param[MAX_STR_SIZE], str_value[MAX_STR_SIZE], help_buf[MAX_STR_SIZE];

        (*i)++;

	ip_n = t[*i].size;

	for (ip_i = 0; ip_i < ip_n; ip_i++) {
        	(*i)++;
		o_n = t[*i].size;
		id = -1;
		for (o_i = 0; o_i < o_n; o_i++) {
        		(*i)++;
                        if (jsoneq(buf, &t[*i], "id") == 0) {
                                (*i)++;
                                continue;
			}
			/* Expect priority to be the ifrst item in JSON object !!!*/
                        if (jsoneq(buf, &t[*i], JSON_PRIORITY) == 0) {
                                (*i)++;
				create_rule(sess, buf, &t[*i], IP_PREFIX, &id);
                                continue;
                        }
			if (id == -1) {
				/* We have a problem here, the rule can not be processed */
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, " Rule is corrupted\n");
                                (*i)++;
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_SRCIP) == 0) {
                                (*i)++;
				handle_string_from_tuple(sess, buf, &t[*i], IP_PREFIX, id, 0, "srcaddr", "");
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_DSTIP) == 0) {
                                (*i)++;
				handle_string_from_tuple(sess, buf, &t[*i], IP_PREFIX, id, 0, "dstaddr", "");
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_SRCNETMASK) == 0) {
                                (*i)++;
				handle_string_from_tuple(sess, buf, &t[*i], IP_PREFIX, id, 0, "srcnetmask", "");
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_DSTNETMASK) == 0) {
                                (*i)++;
				handle_string_from_tuple(sess, buf, &t[*i], IP_PREFIX, id, 0, "dstnetmask", "");
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_SRCPORT) == 0) {
                                (*i)++;
				json_get_int_string(&t[*i],buf, str_value);
				sprintf(str_param, "%snum='%d']/%s[id='%d']/srcport", IP_PREFIX, id, TUPLE, 0);
				if (um_set_value(sess, str_param, str_value) != SR_SUCCESS) 
					CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "ERROR after um_set_value str_param:%s: str_value:%s: \n", str_param, str_value);
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_DSTPORT) == 0) {
                                (*i)++;
				json_get_int_string(&t[*i],buf, str_value);
				sprintf(str_param, "%snum='%d']/%s[id='%d']/dstport", IP_PREFIX, id, TUPLE, 0);
				if (um_set_value(sess, str_param, str_value) != SR_SUCCESS) 
					CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "ERROR after um_set_value str_param:%s: str_value:%s: \n", str_param, str_value);
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_PROTOCOL) == 0) {
                                (*i)++;
				json_get_string(&t[*i], buf, help_buf);
				strcpy(str_value, "0");
				if (!strcmp(help_buf, "TCP"))
					strcpy(str_value, "6");
				if (!strcmp(help_buf, "UDP"))
					strcpy(str_value, "17");
				sprintf(str_param, "%snum='%d']/%s[id='%d']/proto", IP_PREFIX, id, TUPLE, 0);
				if (um_set_value(sess, str_param, str_value) != SR_SUCCESS) 
					CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "ERROR after um_set_value str_param:%s: str_value:%s: \n", str_param, str_value);
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_PROGRAM) == 0) {
                                (*i)++;
				handle_string_from_tuple(sess, buf, &t[*i], IP_PREFIX, id, 0, "program", "*");
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_USER) == 0) {
                                (*i)++;
				handle_string_from_tuple(sess, buf, &t[*i], IP_PREFIX, id, 0, "user", "*");
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_ACTION) == 0) {
                                (*i)++;
				handle_string_from_rule(sess, buf, &t[*i], IP_PREFIX, id, "action");
                                continue;
			}
 			(*i)++;
		} 
	}
}

static void handle_system_policies(sr_session_ctx_t *sess, char *buf, jsmntok_t *t, int *i)
{
	SR_32 s_i, s_n, o_n, o_i, id, tmp;
	char str_param[MAX_STR_SIZE], str_value[MAX_STR_SIZE];

        (*i)++;

	s_n = t[*i].size;

	for (s_i = 0; s_i < s_n; s_i++) {
        	(*i)++;
		o_n = t[*i].size;
		id = -1;
		for (o_i = 0; o_i < o_n; o_i++) {
        		(*i)++;
                        if (jsoneq(buf, &t[*i], "id") == 0) {
                                (*i)++;
                                continue;
			}
			/* Expect priority to be the ifrst item in JSON object !!!*/
                        if (jsoneq(buf, &t[*i], JSON_PRIORITY) == 0) {
                                (*i)++;
				create_rule(sess, buf, &t[*i], FILE_PREFIX, &id);
                                continue;
                        }
			if (id == -1) {
				/* We have a problem here, the rule can not be processed */
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, " Rule is correpted\n");
                                (*i)++;
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_ACTION) == 0) {
                                (*i)++;
				handle_string_from_rule(sess, buf, &t[*i], FILE_PREFIX, id, "action");
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_FILE_NAME) == 0) {
                                (*i)++;
				handle_string_from_tuple(sess, buf, &t[*i], FILE_PREFIX, id, 0, "filename", "");
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_PERMISSIONS) == 0) {
                                (*i)++;
				tmp = json_get_int(&t[*i], buf);
        			sprintf(str_param, "%snum='%d']/%s[id='%d']/%s", FILE_PREFIX, id, TUPLE, 0, "permission");
				sprintf(str_value, "77%d", tmp);
        			if (um_set_value(sess, str_param, str_value) != SR_SUCCESS) {
					CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "ERROR after um_set_value str_param:%s: str_value:%s: \n", str_param, str_value);
				}
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_PROGRAM) == 0) {
                                (*i)++;
				handle_string_from_tuple(sess, buf, &t[*i], FILE_PREFIX, id, 0, "program", "*");
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_USER) == 0) {
                                (*i)++;
				handle_string_from_tuple(sess, buf, &t[*i], FILE_PREFIX, id, 0, "user", "*");
                                continue;
			}
        		(*i)++;
		} 
	}
}

static void convert_tolower(char *s)
{
	for (; *s; s++)
		*s = (char)tolower(*s);
}

static void handle_can_policies(sr_session_ctx_t *sess, char *buf, jsmntok_t *t, int *i)
{
	SR_32 c_i, c_n, o_n, o_i, id;
	char str_param[MAX_STR_SIZE], str_value[MAX_STR_SIZE];

 	(*i)++;

	c_n = t[*i].size;

	for (c_i = 0; c_i < c_n; c_i++) {
        	(*i)++;
		o_n = t[*i].size;
		id = -1;
		for (o_i = 0; o_i < o_n; o_i++) {
			(*i)++;
			if (jsoneq(buf, &t[*i], "id") == 0) {
				(*i)++;
				continue;
			}
			if (jsoneq(buf, &t[*i], JSON_PRIORITY) == 0) {
				(*i)++;
				create_rule(sess, buf, &t[*i], CAN_PREFIX, &id);
				continue;
			}
			if (id == -1) {
				/* We have a problem here, the rule can not be processed */
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "Rule is correpted\n");
				(*i)++;
				continue;
			}
			if (jsoneq(buf, &t[*i], JSON_ACTION) == 0) {
				(*i)++;
				handle_string_from_rule(sess, buf, &t[*i], CAN_PREFIX, id, "action");
				continue;
			}
			if (jsoneq(buf, &t[*i], JSON_CAN_MESSAGE_ID) == 0) {
				(*i)++;
				json_get_string(&t[*i], buf, str_value);
				if (!strcmp(str_value, "-1"))
					strcpy(str_value, "any");
				sprintf(str_param, "%snum='%d']/%s[id='%d']/%s", CAN_PREFIX, id, TUPLE, 0, "msg_id");
				if (um_set_value(sess, str_param, str_value) != SR_SUCCESS) {
					CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "ERROR after um_set_value str_param:%s: str_value:%s: \n", str_param, str_value);
					continue;
				}
				continue;
			}
			if (jsoneq(buf, &t[*i], JSON_CAN_DIRECTION) == 0) {
				(*i)++;
				json_get_string(&t[*i], buf, str_value);
				convert_tolower(str_value);
				sprintf(str_param, "%snum='%d']/%s[id='%d']/%s", CAN_PREFIX, id, TUPLE, 0, "direction");
				if (um_set_value(sess, str_param, str_value) != SR_SUCCESS) {
					CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "ERROR after um_set_value str_param:%s: str_value:%s: \n", str_param, str_value);
					continue;
				}
				continue;
			}
			if (jsoneq(buf, &t[*i], JSON_PROGRAM) == 0) {
				(*i)++;
				handle_string_from_tuple(sess, buf, &t[*i], CAN_PREFIX, id, 0, "program", "*");
				continue;
			}
			if (jsoneq(buf, &t[*i], JSON_USER) == 0) {
				(*i)++;
				handle_string_from_tuple(sess, buf, &t[*i], CAN_PREFIX, id, 0, "user", "*");
				continue;
			}
			(*i)++;
		} 
	}
}

static SR_32 parse_json(sr_session_ctx_t *sess, char *buf, SR_U32 *version)
{
	SR_32 i, r, rc;
	jsmn_parser p;
	jsmntok_t *t = NULL;

	jsmn_init(&p);
	r = jsmn_parse(&p, buf, strlen(buf), NULL, 0);
	if (r < 0) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "Failed to parse JSON: %d\n", r);
		return SR_ERROR;
	}
#ifdef JSON_DEBUG
	printf("Json parse r:%d \n", r);
#endif
	if (!(t = malloc(r * sizeof(jsmntok_t)))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "Failed alloc memory:\n");
		return SR_ERROR;
	}
	jsmn_init(&p);
	r = jsmn_parse(&p, buf, strlen(buf), t, r);
	if (r < 0) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "Failed to parse JSON: %d", r);
		rc = SR_ERROR;
		goto out;
	}
        for (i = 0; i < r ; i++) {
		if (jsoneq(buf, &t[i], ACTION_VER) == 0) {
			i++;
			*version = (SR_U32)json_get_int(&t[i], buf);
			if (*version == static_policy_version)
				goto out;
#ifdef JSON_DEBUG
			printf("New version :%d version:%d buf:%s:\n", *version, static_policy_version, buf);
#endif
			rc = sr_delete_item(sess, "/saferide:config", SR_EDIT_DEFAULT);
			if (SR_ERR_OK != rc) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "sr_delete_item: %s\n", sr_strerror(rc));
				return SR_ERROR;
			}
		}
		if (jsoneq(buf, &t[i], IP_VER) == 0) {
			i++;
		}
		if (jsoneq(buf, &t[i], CAN_VER) == 0) {
			i++;
		}
		if (jsoneq(buf, &t[i], SYSTEM_VER) == 0) {
			i++;
		}
		if (jsoneq(buf, &t[i], ACTIONS) == 0) {
			handle_actions(sess, buf, t, &i);
		}
		if (jsoneq(buf, &t[i], IP_POLICIES) == 0) {
			handle_ip_policies(sess, buf, t, &i);
		}
		if (jsoneq(buf, &t[i], CAN_POLICIES) == 0) {
			handle_can_policies(sess, buf, t, &i);
		}
		if (jsoneq(buf, &t[i], SYSTEM_POLICIES) == 0) {
			handle_system_policies(sess, buf, t, &i);
		}
	}

	 /* commit the changes */
	rc = sr_commit(sess);
	if (SR_ERR_OK != rc) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "ERROR sr_commit: %s", sr_strerror(rc));
		rc = SR_ERROR;
		goto out;
	}

	rc = sr_copy_config(sess, "saferide", SR_DS_RUNNING, SR_DS_STARTUP);
	if (SR_ERR_OK != rc) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "EROOR sr_copy_config: %s\n", sr_strerror(rc));
		rc = SR_ERROR;
		goto out;
	}

out:
	if (t)
		free(t);
	return rc;
}

static SR_32 get_server_db(sr_session_ctx_t *sess)
{
	CURL *curl;
	CURLcode res;
	struct curl_slist *chunk = NULL;
	char ip_version[STATIC_POLICY_VERSION_SIZE], system_version[STATIC_POLICY_VERSION_SIZE], can_version[STATIC_POLICY_VERSION_SIZE], action_version[STATIC_POLICY_VERSION_SIZE];
	SR_U32 new_version = 0;
 	struct curl_httppost* post = NULL, *last = NULL; 
	struct curl_fetch_st curl_fetch = {};
	struct curl_fetch_st *fetch = &curl_fetch;
	char post_vin[64];
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
	snprintf(post_vin, 64, "X-VIN: %s", config_params.vin);
	chunk = curl_slist_append(chunk, post_vin);
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
	parse_json(sess, fetch->payload, &new_version);
	if (new_version != static_policy_version) {
		static_policy_version = new_version;
		if (set_version_to_file(new_version) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,  "FAILED setting new version");
		}
	}

out:
	SR_CURL_DEINIT(curl);
	if (fetch->payload)
		free(fetch->payload);

	return SR_SUCCESS;
}

SR_32 database_management(void *p)
{
	sr_conn_ctx_t *conn = NULL;
	sr_session_ctx_t *sess = NULL;
	int rc;

	sr_log_stderr(SR_LL_NONE/*SR_LL_DBG/SR_LL_WRN*/);

	/* connect to sysrepo */
	rc = sr_connect("update_manager", SR_CONN_DEFAULT, &conn);
	if (SR_ERR_OK != rc) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "databse management ERROR sr_connect");
        	return SR_ERROR;
	}
	rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &sess);
    	if (SR_ERR_OK != rc) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,  "sr_session_start failed: %s\n", sr_strerror(rc));
        	goto cleanup;
    	}
    	rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &sess);
    	if (SR_ERR_OK != rc) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,  "sr_session_start failed: %s\n", sr_strerror(rc));
        	goto cleanup;
    	}

	while (is_run_db_mng) { 
		if (get_server_db(sess) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,  "get_server_db_failed:");
		}
		sleep(1);
	}

cleanup:
	if (NULL != sess) {
		sr_session_stop(sess);
	}
	if (NULL != conn) {
		sr_disconnect(conn);
	}
	return SR_ERROR;
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
