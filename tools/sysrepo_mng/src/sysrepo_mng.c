#include <sysrepo_mng.h>
#include <sysrepo.h>
#include "sr_cls_network_common.h"
#include "sr_actions_common.h"
#include "sr_msg.h"
#include "sentry.h"
#include "action.h"
#include "ip_rule.h"
#include "file_rule.h"
#include "can_rule.h"
#include "jsmn.h"
#include <string.h>
#include <ctype.h>
#include "sr_cls_wl_common.h"

#ifdef NO_CEF
#define REASON 		"reason" // shut up GCC
#define MESSAGE 	"msg" // shut up GCC AGAIN
#define CEF_log_event(f1, f2, f3, ...) printf(__VA_ARGS__)
#else
#include "sr_log.h"
#endif

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
#define JSON_INTERFACE "canInterface"
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
#define JSON_ACTION "actionName"
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
    {"interface", SR_STRING_T, ""},
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
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, 
				"%s=this type (%d) not supported",REASON,
				value.type);
			rc = SR_ERR_UNSUPPORTED;
			break;
		}

		if (rc == SR_ERR_OK) {
			/* set the default value */
			rc = sr_set_item(sess, param_xpath, &value, SR_EDIT_DEFAULT);
			if (SR_ERR_OK != rc) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=sr_set_item %s: %s",REASON,
					param_xpath,sr_strerror(rc));
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
	CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
		"%s=unsupported value type",REASON);
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
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=can't get type of %s", REASON,
				str_param);
			break;
	}

        if (ptr) {
                if (set_default_params(sess, str_param, ptr, array_size) != SR_ERR_OK) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=setting new item params to default",REASON);
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
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=str_param:%s sr_get_item %s:", REASON,
			str_param, sr_strerror(rc));
		return rc;
	}
	memset(&new_val, 0, sizeof(sr_val_t));
	new_val.type = value->type;
	sr_free_val(value);

	rc = set_str_value(&new_val, str_value);
	if (rc != SR_ERR_OK) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=set_str_value failed to set %s to %s: %s",REASON,
			str_param, str_value, sr_strerror(rc));
		return rc;
	}

	rc = sr_set_item(sess, str_param, &new_val, SR_EDIT_DEFAULT);
	if (SR_ERR_OK != rc) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sr_set_item %s to %s: %s",REASON,
			str_param,str_value, sr_strerror(rc));
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
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=sr_set_item %s: %s", REASON,
				str_param, sr_strerror(rc));
            continue;
		}

		sprintf(str_param, "/%s/%s/%s[name='%s']", DB_PREFIX, SR_ACTIONS, LIST_ACTIONS, action_name);
		rc = set_default_params(sess, str_param, default_action_params, ARRAYSIZE(default_action_params));
                if (rc != SR_ERR_OK) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=etting new item params to default",REASON);
			continue; 
		}

		strncpy(str_value, is_drop ? JSON_ACTION_DROP : JSON_ACTION_ALLOW, MAX_STR_SIZE);
		sprintf(str_param, "/%s/%s/%s[name='%s']/%s", DB_PREFIX, SR_ACTIONS, LIST_ACTIONS, action_name, ACTION);

		if (um_set_value(sess, str_param, str_value) != SR_SUCCESS)  {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=after um_set_value str_param:%s: str_value:%s:",REASON,
				str_param, str_value);
			continue;
		}

		if (!is_log)
			continue;

		sprintf(str_param, "/%s/%s/%s[name='%s']/%s", DB_PREFIX, SR_ACTIONS, LIST_ACTIONS, action_name, LOG_FACILITY);
		strcpy(str_value, "syslog");

		if (um_set_value(sess, str_param, str_value) != SR_SUCCESS) 
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=after um_set_value str_param:%s: str_value:%s",REASON,
				str_param, str_value);
        }
}

static SR_32 create_rule(sr_session_ctx_t *sess, char *buf, jsmntok_t *t, char *prefix, SR_32 *rule_id, SR_U32 max_id)
{
	SR_32 id;
	char str_param[MAX_STR_SIZE];

	id = json_get_int(t, buf);
	if (id > max_id) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=Create rule failed id is bigger then max.",REASON); 
		*rule_id = id;
		return SR_ERROR;
	}
	sprintf(str_param, "%snum='%d']", prefix, id);
	if (um_set_param(sess, str_param) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=ip policies : um_set_param failed",REASON); 
		return SR_ERROR;
	}
	sprintf(str_param, "%snum='%d']/%s[id='%d']", prefix, id, TUPLE, 0);
	if (um_set_param(sess, str_param) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=ip policies : um_set_param failed",REASON); 
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
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=after um_set_value str_param:%s: str_value:%s:", REASON,
			str_param, str_value);
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
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=after um_set_value str_param:%s: str_value:%s:",REASON,
			str_param, str_value);
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
			create_rule(sess, buf, &t[*i], IP_PREFIX, &id, SR_IP_WL_START_RULE_NO - 1);
                                continue;
                        }
			if (id == -1) {
				/* We have a problem here, the rule can not be processed */
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, 
					"%s=rule is corrupted",REASON);
                                (*i)++;
                                continue;
			}
			if (id >= SR_IP_WL_START_RULE_NO) {
				/* Rule id exceed max value */
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, 
					"%s= IP rule id :%d exceeds max value (%d)",REASON, id, SR_IP_WL_START_RULE_NO - 1);
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
					CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, 
						"%s=after um_set_value str_param:%s: str_value:%s:",REASON,
						str_param, str_value);
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_DSTPORT) == 0) {
                                (*i)++;
				json_get_int_string(&t[*i],buf, str_value);
				sprintf(str_param, "%snum='%d']/%s[id='%d']/dstport", IP_PREFIX, id, TUPLE, 0);
				if (um_set_value(sess, str_param, str_value) != SR_SUCCESS) 
					CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=after um_set_value str_param:%s: str_value:%s:",REASON,
						str_param, str_value);
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
					CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=after um_set_value str_param:%s: str_value:%s:", REASON,
						str_param, str_value);
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
				create_rule(sess, buf, &t[*i], FILE_PREFIX, &id, SR_FILE_WL_START_RULE_NO - 1);
                                continue;
                        }
			if (id == -1) {
				/* We have a problem here, the rule can not be processed */
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=rule is correpted",REASON);
                                (*i)++;
                                continue;
			}
			if (id >= SR_FILE_WL_START_RULE_NO) {
				/* Rule id exceed max value */
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, 
					"%s= FILE rule id :%d exceeds max value (%d)",REASON, id, SR_CAN_WL_START_RULE_NO - 1);
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
					CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=after um_set_value str_param:%s: str_value:%s:", REASON,
						str_param, str_value);
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
				create_rule(sess, buf, &t[*i], CAN_PREFIX, &id, SR_CAN_WL_START_RULE_NO - 1);
				continue;
			}
			if (id == -1) {
				/* We have a problem here, the rule can not be processed */
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=rule is correpted",REASON);
				(*i)++;
				continue;
			}
			if (id >= SR_CAN_WL_START_RULE_NO) {
				/* Rule id exceed max value */
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, 
					"%s= CAN rule id :%d exceeds max value (%d)",REASON, id, SR_CAN_WL_START_RULE_NO - 1);
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
				if (strcmp(str_value, "-1") == 0 || strcmp(str_value, "null") == 0)
					strcpy(str_value, "any");
				sprintf(str_param, "%snum='%d']/%s[id='%d']/%s", CAN_PREFIX, id, TUPLE, 0, "msg_id");
				if (um_set_value(sess, str_param, str_value) != SR_SUCCESS) {
					CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=after um_set_value str_param:%s: str_value:%s:",REASON,
						str_param, str_value);
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
					CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=after um_set_value str_param:%s: str_value:%s:", REASON,
						str_param, str_value);
					continue;
				}
				continue;
			}
			if (jsoneq(buf, &t[*i], JSON_INTERFACE) == 0) {
				(*i)++;
				handle_string_from_tuple(sess, buf, &t[*i], CAN_PREFIX, id, 0, "interface", "*");
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

static SR_32 sysrepo_mng_delete_rules(sysrepo_mng_handler_t *handler, char *prefix, SR_U32 start, SR_U32 end)
{
	SR_32 i, rc;
	char str_param[MAX_STR_SIZE];

	for (i = start; i < end; i++) {
		sprintf(str_param, "%snum='%d']", prefix, i);
		if ((rc = sr_delete_item(handler->sess, str_param, SR_EDIT_DEFAULT)) != SR_ERR_OK) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=sr_delete_item: %s", REASON, sr_strerror(rc));
		}
	}

	return SR_SUCCESS;
}

SR_32 sys_repo_mng_delete_ip_rules(sysrepo_mng_handler_t *handler, SR_32 start, SR_32 end)
{
	return sysrepo_mng_delete_rules(handler, IP_PREFIX, start, end); 
}

SR_32 sys_repo_mng_delete_file_rules(sysrepo_mng_handler_t *handler, SR_32 start, SR_32 end)
{
	return sysrepo_mng_delete_rules(handler, FILE_PREFIX, start, end); 
}

SR_32 sys_repo_mng_delete_can_rules(sysrepo_mng_handler_t *handler, SR_32 start, SR_32 end)
{
	return sysrepo_mng_delete_rules(handler, CAN_PREFIX, start, end); 
}

SR_32 sysrepo_mng_delete_db(sysrepo_mng_handler_t *handler)
{
	SR_32 rc;
	char str_param[MAX_STR_SIZE];
	
	/* Delete all actions, recrate WL action */
	sprintf(str_param, "/%s/%s/%s", DB_PREFIX, SR_ACTIONS, LIST_ACTIONS);
	rc = sr_delete_item(handler->sess, str_param, SR_EDIT_DEFAULT);
	if (SR_ERR_OK != rc) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sr_delete_item: %s", REASON, sr_strerror(rc));
		return SR_ERROR;
	}
	if (sys_repo_mng_create_action(handler, WHITE_LIST_ACTION, SR_TRUE, SR_TRUE) != SR_ERR_OK) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=sr_white_list_create_action: sys_repo_mng_create_action failed",REASON);
                return SR_ERROR;
        }

	printf("Delete rules 0%% ...");
	sysrepo_mng_delete_rules(handler, FILE_PREFIX, 0, SR_FILE_WL_START_RULE_NO);
	printf("\rDelete rules 33%% ...");
	sysrepo_mng_delete_rules(handler, IP_PREFIX, 0, SR_IP_WL_START_RULE_NO);
	printf("\rDelete rules 66%% ...");
	sysrepo_mng_delete_rules(handler, CAN_PREFIX, 0, SR_CAN_WL_START_RULE_NO);
	printf("\rDelete rules 100%% \n");

	return SR_SUCCESS;
}

SR_32 sysrepo_mng_delete_all(sysrepo_mng_handler_t *handler, SR_BOOL is_commit)
{
	char str_param[MAX_STR_SIZE];
	SR_32 rc;

	sprintf(str_param, "/%s", DB_PREFIX);
	rc = sr_delete_item(handler->sess, str_param, SR_EDIT_DEFAULT);
	if (SR_ERR_OK != rc) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s= Delete all failed : %s", REASON, sr_strerror(rc));
		return SR_ERROR;
	}
	if (!is_commit)
		return SR_SUCCESS;

	rc = sr_commit(handler->sess);
	if (SR_ERR_OK != rc) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sr_commit: %s",REASON,
			sr_strerror(rc));
		rc = SR_ERROR;
		goto out;
	}

	rc = sr_copy_config(handler->sess, "saferide", SR_DS_RUNNING, SR_DS_STARTUP);
	if (SR_ERR_OK != rc) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sr_copy_config: %s",REASON,
			sr_strerror(rc));
		rc = SR_ERROR;
		goto out;
	}

out:
	return SR_SUCCESS;
}


SR_32 sysrepo_mng_parse_json(sysrepo_mng_handler_t *handler, char *buf, SR_U32 *version, SR_U32 old_version)
{
	SR_32 i, r, rc;
	jsmn_parser p;
	jsmntok_t *t = NULL;
	sr_session_ctx_t *sess;

	
	if (!handler)
		return SR_ERROR;
	sess = handler->sess;

	jsmn_init(&p);
	r = jsmn_parse(&p, buf, strlen(buf), NULL, 0);
	if (r < 0) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to parse JSON: %d",REASON,
			r);
		return SR_ERROR;
	}
#ifdef JSON_DEBUG
	printf("Json parse r:%d \n", r);
#endif
	if (!(t = malloc(r * sizeof(jsmntok_t)))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, 
			"%s=failed alloc memory",REASON);
		return SR_ERROR;
	}
	jsmn_init(&p);
	r = jsmn_parse(&p, buf, strlen(buf), t, r);
	if (r < 0) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to parse JSON: %d",REASON,
			r);
		rc = SR_ERROR;
		goto out;
	}
        for (i = 0; i < r ; i++) {
		if (jsoneq(buf, &t[i], ACTION_VER) == 0) {
			i++;
			if (version) {
				*version = (SR_U32)json_get_int(&t[i], buf);
				if (*version == old_version)
					goto out;
				CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
					"%s=new version :%d version:%d buf:%s",MESSAGE,*version, old_version, buf);
			}
			rc = sysrepo_mng_delete_db(handler);
			if (SR_ERR_OK != rc) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=sr_delete_item: %s", REASON,
					sr_strerror(rc));
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
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sr_commit: %s",REASON,
			sr_strerror(rc));
		rc = SR_ERROR;
		goto out;
	}

	rc = sr_copy_config(sess, "saferide", SR_DS_RUNNING, SR_DS_STARTUP);
	if (SR_ERR_OK != rc) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sr_copy_config: %s",REASON,
			sr_strerror(rc));
		rc = SR_ERROR;
		goto out;
	}

out:
	if (t)
		free(t);
	return rc;
}

SR_32 sysrepo_mng_session_start(sysrepo_mng_handler_t *handler)
{ 
        int rc;

        sr_log_stderr(SR_LL_NONE/*SR_LL_DBG/SR_LL_WRN*/);

	handler->conn = NULL;
	handler->sess = NULL;

        /* connect to sysrepo */
        rc = sr_connect("update_manager", SR_CONN_DEFAULT, &(handler->conn));
        if (SR_ERR_OK != rc) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=databse management ERROR sr_connect",REASON);
                return SR_ERROR;
        }
        rc = sr_session_start(handler->conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &(handler->sess));
        if (SR_ERR_OK != rc) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=sr_session_start failed: %s",REASON,
					sr_strerror(rc));
                sr_disconnect(handler->conn);
                return SR_ERROR;
        }

	return SR_SUCCESS;
}

SR_32 sysrepo_mng_session_end(sysrepo_mng_handler_t *handler)
{
        if (NULL != handler->sess) {
                sr_session_stop(handler->sess);
		handler->sess = NULL;
        }
        if (NULL != handler->conn) {
                sr_disconnect(handler->conn);
		handler->conn = NULL;
	}

	return SR_SUCCESS;
}

SR_U8 sys_repo_mng_perm_get_code(char *perms)
{
	SR_8 help;
	SR_U8 res = 0;
	
	if (!perms || strlen(perms) != 3)
		return 0;

	help = atoi(perms + 2);
	if(help & 4)
		res |= SR_FILEOPS_READ;
	if(help & 2)
		res |= SR_FILEOPS_WRITE;
	if(help & 1)
		res |= SR_FILEOPS_EXEC;

	return res;
}

static void file_op_convert(SR_U8 file_op, char *perms)
{
	SR_U8 res = 0;

	if (file_op & SR_FILEOPS_READ) 
		res |= 4;
	if (file_op & SR_FILEOPS_WRITE) 
		res |= 2;
	if (file_op & SR_FILEOPS_EXEC) 
		res |= 1;

	sprintf(perms, "77%d", res);
}

#define ADD_FILE_FIELD(fieldname, fieldvalue) \
	sprintf(str_param, "%snum='%d']/%s[id='%d']/%s", FILE_PREFIX, rule_id, TUPLE, tuple, fieldname); \
        if (um_set_value(handler->sess, str_param, fieldvalue) != SR_SUCCESS) { \
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, \
                        "%s=after um_set_value str_param:%s: ", REASON, str_param); \
                return SR_ERROR; \
        }

#define ADD_NET_FIELD(tuple, fieldname, fieldvalue) \
	sprintf(str_param, "%snum='%d']/%s[id='%d']/%s", IP_PREFIX, rule_id, TUPLE, tuple, fieldname); \
        if (um_set_value(handler->sess, str_param, fieldvalue) != SR_SUCCESS) { \
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, \
                        "%s=after um_set_value str_param:%s: ", REASON, str_param); \
                return SR_ERROR; \
        }

SR_32 sys_repo_mng_create_file_rule(sysrepo_mng_handler_t *handler, SR_32 rule_id, SR_32 tuple, char *file_name, char *exec, char *user, char *action, SR_U8 file_op)
{
	char str_param[MAX_STR_SIZE];
	char perms[4];

	file_op_convert(file_op, perms);
	sprintf(str_param, "%snum='%d']", FILE_PREFIX, rule_id);
	if (um_set_param(handler->sess, str_param) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=create rule : um_set_param failed",REASON);
		return SR_ERROR;
	}
	sprintf(str_param, "%snum='%d']/%s[id='%d']", FILE_PREFIX, rule_id, TUPLE, tuple);
	if (um_set_param(handler->sess, str_param) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=rule_create : um_set_param failed",REASON);
		return SR_ERROR;
	}
	
	sprintf(str_param, "%snum='%d']/%s", FILE_PREFIX, rule_id, "action");
	if (um_set_value(handler->sess, str_param, action) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=after um_set_value str_param:%s: action",REASON, str_param);
		return SR_ERROR;
	}

	ADD_FILE_FIELD("filename", file_name) 
	ADD_FILE_FIELD("program", exec) 
	ADD_FILE_FIELD("user", user) 
	ADD_FILE_FIELD("permission", perms) 

	return SR_SUCCESS;
}

SR_32 sys_repo_mng_create_net_rule(sysrepo_mng_handler_t *handler, SR_32 rule_id, SR_32 tuple, char *src_addr, char *src_netmask,
	char *dst_addr, char *dst_netmask, SR_U8 ip_proto, SR_U16 src_port, SR_U16 dst_port, char *exec, char *user, char *action)
{
	char str_param[MAX_STR_SIZE], str_help[MAX_STR_SIZE];

	sprintf(str_param, "%snum='%d']", IP_PREFIX, rule_id);
	if (um_set_param(handler->sess, str_param) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=create rule : um_set_param failed",REASON);
		return SR_ERROR;
	}
	
	sprintf(str_param, "%snum='%d']/%s", IP_PREFIX, rule_id, "action");
	if (um_set_value(handler->sess, str_param, action) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=after um_set_value str_param:%s: action",REASON, str_param);
		return SR_ERROR;
	}
	
	sprintf(str_param, "%snum='%d']/%s[id='%d']", IP_PREFIX, rule_id, TUPLE, tuple);
	if (um_set_param(handler->sess, str_param) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=rule_create : um_set_param failed",REASON);
		return SR_ERROR;
	}

	ADD_NET_FIELD(tuple, "srcaddr", src_addr) 
	ADD_NET_FIELD(tuple, "dstaddr", dst_addr) 
	ADD_NET_FIELD(tuple, "srcnetmask", src_netmask) 
	ADD_NET_FIELD(tuple, "dstnetmask", dst_netmask) 
	ADD_NET_FIELD(tuple, "program", exec) 
	ADD_NET_FIELD(tuple, "user", user) 
	sprintf(str_help, "%d", ip_proto);
	ADD_NET_FIELD(tuple, "proto", str_help) 
	sprintf(str_help, "%d", src_port);
	ADD_NET_FIELD(tuple, "srcport", str_help) 
	sprintf(str_help, "%d", dst_port);
	ADD_NET_FIELD(tuple, "dstport", str_help) 

	return SR_SUCCESS;
}

static void can_packet_convert(SR_U32 msg_id,SR_U8 dir, char * msgid_str,char * dir_str)
{
	sprintf(msgid_str, "%08x", msg_id);
	sprintf(dir_str, "%s", dir==0?"in":"out");
}

#define ADD_CAN_FIELD(fieldname, fieldvalue, tuple) \
	sprintf(str_param, "%snum='%d']/%s[id='%d']/%s", CAN_PREFIX, rule_id, TUPLE, tuple, fieldname); \
        if (um_set_value(handler->sess, str_param, fieldvalue) != SR_SUCCESS) { \
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, \
                        "%s=after um_set_value str_param:%s: ", REASON, str_param); \
                return SR_ERROR; \
        }



SR_32 sys_repo_mng_create_canbus_rule(sysrepo_mng_handler_t *handler, SR_32 rule_id, SR_U32 tuple_id, SR_U32 msg_id, char *interface, char *exec, char *user, char *action, SR_U8 dir)
{
	char str_param[MAX_STR_SIZE];
	char msgid_str[9];
	char dir_str[4];
	can_packet_convert(msg_id,dir, msgid_str,dir_str);
	
	sprintf(str_param, "%snum='%d']", CAN_PREFIX, rule_id);
	if (um_set_param(handler->sess, str_param) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=create rule : um_set_param failed",REASON);
		return SR_ERROR;
	}
	sprintf(str_param, "%snum='%d']/%s[id='%d']", CAN_PREFIX, rule_id, TUPLE, tuple_id);
	if (um_set_param(handler->sess, str_param) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=rule_create : um_set_param failed",REASON);
		return SR_ERROR;
	}
	
	sprintf(str_param, "%snum='%d']/%s", CAN_PREFIX, rule_id, "action");
	if (um_set_value(handler->sess, str_param, action) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=after um_set_value str_param:%s: action",REASON, str_param);
		return SR_ERROR;
	}

	ADD_CAN_FIELD("msg_id", msgid_str, tuple_id) 
	ADD_CAN_FIELD("direction", dir_str, tuple_id)
	ADD_CAN_FIELD("interface", interface, tuple_id)
	ADD_CAN_FIELD("user", user, tuple_id) 	
	ADD_CAN_FIELD("program", exec, tuple_id) 
	
	return SR_SUCCESS;
}
SR_32 sys_repo_mng_commit(sysrepo_mng_handler_t *handler)
{
	SR_32 rc;

	rc = sr_commit(handler->sess);
	if (SR_ERR_OK != rc) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sr_commit: %s",REASON,
			sr_strerror(rc));
		return SR_ERROR;
	}

	rc = sr_copy_config(handler->sess, "saferide", SR_DS_RUNNING, SR_DS_STARTUP);
	if (SR_ERR_OK != rc) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sr_copy_config: %s",REASON,
			sr_strerror(rc));
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

SR_32 sys_repo_mng_create_action(sysrepo_mng_handler_t *handler, char *action_name, SR_BOOL is_allow, SR_BOOL is_log)
{
	char str_param[MAX_STR_SIZE], str_value[MAX_STR_SIZE];
	SR_32 rc;

	sprintf(str_param, "/%s/%s/%s[name='%s']", DB_PREFIX, SR_ACTIONS, LIST_ACTIONS, action_name);
	rc = sr_set_item(handler->sess, str_param, NULL, SR_EDIT_DEFAULT);
	if (SR_ERR_OK != rc) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
		"%s=sr_set_item %s: %s", REASON,
		str_param, sr_strerror(rc));
		return SR_ERROR;
	}

	sprintf(str_param, "/%s/%s/%s[name='%s']", DB_PREFIX, SR_ACTIONS, LIST_ACTIONS, action_name);
	rc = set_default_params(handler->sess, str_param, default_action_params, ARRAYSIZE(default_action_params));
	if (rc != SR_ERR_OK) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=setting new item params to default",REASON);
		return SR_ERROR;
	}
	strncpy(str_value, is_allow ? JSON_ACTION_ALLOW : JSON_ACTION_DROP, MAX_STR_SIZE);
	sprintf(str_param, "/%s/%s/%s[name='%s']/%s", DB_PREFIX, SR_ACTIONS, LIST_ACTIONS, action_name, ACTION);
	if (um_set_value(handler->sess, str_param, str_value) != SR_SUCCESS)  {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=after um_set_value str_param:%s: str_value:%s:",REASON,
			str_param, str_value);
		return SR_ERROR;
	}

	sprintf(str_param, "/%s/%s/%s[name='%s']/%s", DB_PREFIX, SR_ACTIONS, LIST_ACTIONS, action_name, LOG_FACILITY);
	strcpy(str_value, is_log ? "syslog" : "none");
	if (um_set_value(handler->sess, str_param, str_value) != SR_SUCCESS) { 
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=after um_set_value str_param:%s: str_value:%s",REASON,
			str_param, str_value);
		return SR_ERROR;
	}

	return SR_SUCCESS;
}
