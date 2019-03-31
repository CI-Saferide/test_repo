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
#include "redis_mng.h"
#include "sr_cls_wl_common.h"
#include "db_tools.h"
#include "sr_config.h"
#include "read.h"

#ifdef NO_CEF
#define REASON 		"reason" // shut up GCC
#define MESSAGE 	"msg" // shut up GCC AGAIN
#define CEF_log_event(f1, f2, f3, ...) printf(__VA_ARGS__)
#else
#include "sr_log.h"
#endif

#define AUTH		"O5TBQ23IBTIGBV9WWAHTG9824G"
#define DEL			"205Y38YHBJNSNBNESROTHY309HL"

#define PASS_128	"a95qaewbe13dr68tayb45u63i8o9fepac[b]0069 \
					 ea4s1bcd7ef8g90chfbj8k40flc;02d'5/2be.45 \
					 ,4m299n41bcvc15vf5c9xe41zcb17`ef63c5425= \
					 /-.0,m7v"

#define ENGINE		 	"engine"
#define ACTION_PREFIX   "a:"
#define LIST_PREFIX		"l:"
// rule types
#define CAN_PREFIX   	"c:"
#define NET_PREFIX    	"n:"
#define FILE_PREFIX  	"f:"
// fields
#define PROGRAM_ID 		"prog"
#define USER_ID 		"user"
#define ACTION 			"act"
#define IN_INTERFACE 	"in"
#define OUT_INTERFACE 	"out"
#define RATE_LIMIT		"rl"
// CAN rule specific fields
#define MID 			"mid"
// IP rule specific fields
#define SRC_ADDR		"sa"
#define DST_ADDR	 	"da"
#define PROTOCOL 		"prot"
#define SRC_PORT		"sp"
#define DST_PORT	 	"dp"
#define UP_RL		 	"url"
#define DOWN_RL	 		"drl"
// file rule specific fields
#define FILENAME		"file"
#define PERMISSION	 	"perm"
// action specific fields
#define ACTION_BITMAP	"abm"
#define ACTION_LOG		"al"
//#define LOG_FACILITY	"al"
//#define LOG_SEVERITY	"ls"
#define RL_BITMAP 		"rlbm"
#define RL_LOG	 		"rll"
//#define SMS		 	"sms"
//#define EMAIL	 		"mail"

#define SYSTEM_POLICER_PREFIX   	"sp:"
#define SP_UTIME 			"utime"
#define SP_STIME 			"stime"
#define SP_BYTES_READ 		"br"
#define SP_BYTES_WRITE 		"bw"
#define SP_VM_ALLOC 		"vma"
#define SP_THREADS_NO 		"tn"

static int redis_changes;

#if 0
#define IP "ip"
#define NET "net"
#define RULE "rule"
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
#endif

// for JSON
#if 0
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
#endif

#if 0
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
    } else if (strncmp(entry, NET_PREFIX, strlen(NET_PREFIX)) == 0) {
        *p_type = TYPE_IP;
        *p_sub_type = SUB_TYPE_RULE;
        len = strlen(NET_PREFIX);
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
			ptr = deSR_UINT8_Tfault_action_params;
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
#endif

// to get policy from server
#if 0
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
			create_rule(sess, buf, &t[*i], NET_PREFIX, &id, SR_IP_WL_START_RULE_NO - 1);
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
				handle_string_from_tuple(sess, buf, &t[*i], NET_PREFIX, id, 0, "srcaddr", "");
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_DSTIP) == 0) {
                                (*i)++;
				handle_string_from_tuple(sess, buf, &t[*i], NET_PREFIX, id, 0, "dstaddr", "");
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_SRCNETMASK) == 0) {
                                (*i)++;
				handle_string_from_tuple(sess, buf, &t[*i], NET_PREFIX, id, 0, "srcnetmask", "");
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_DSTNETMASK) == 0) {
                                (*i)++;
				handle_string_from_tuple(sess, buf, &t[*i], NET_PREFIX, id, 0, "dstnetmask", "");
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_SRCPORT) == 0) {
                                (*i)++;
				json_get_int_string(&t[*i],buf, str_value);
				sprintf(str_param, "%snum='%d']/%s[id='%d']/srcport", NET_PREFIX, id, TUPLE, 0);
				if (um_set_value(sess, str_param, str_value) != SR_SUCCESS) 
					CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, 
						"%s=after um_set_value str_param:%s: str_value:%s:",REASON,
						str_param, str_value);
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_DSTPORT) == 0) {
                                (*i)++;
				json_get_int_string(&t[*i],buf, str_value);
				sprintf(str_param, "%snum='%d']/%s[id='%d']/dstport", NET_PREFIX, id, TUPLE, 0);
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
				sprintf(str_param, "%snum='%d']/%s[id='%d']/proto", NET_PREFIX, id, TUPLE, 0);
				if (um_set_value(sess, str_param, str_value) != SR_SUCCESS) 
					CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=after um_set_value str_param:%s: str_value:%s:", REASON,
						str_param, str_value);
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_PROGRAM) == 0) {
                                (*i)++;
				handle_string_from_tuple(sess, buf, &t[*i], NET_PREFIX, id, 0, "program", "*");
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_USER) == 0) {
                                (*i)++;
				handle_string_from_tuple(sess, buf, &t[*i], NET_PREFIX, id, 0, "user", "*");
                                continue;
			}
                        if (jsoneq(buf, &t[*i], JSON_ACTION) == 0) {
                                (*i)++;
				handle_string_from_rule(sess, buf, &t[*i], NET_PREFIX, id, "action");
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
#endif

// used by wl
// todo implement
#if 0
static SR_32 redis_mng_delete_rules(redis_mng_handler_t *handler, char *prefix, SR_U32 start, SR_U32 end)
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

SR_32 redis_mng_delete_ip_rules(redis_mng_handler_t *handler, SR_32 start, SR_32 end)
{
	return redis_mng_delete_rules(handler, NET_PREFIX, start, end);
}

SR_32 redis_mng_delete_file_rules(redis_mng_handler_t *handler, SR_32 start, SR_32 end)
{
	return redis_mng_delete_rules(handler, FILE_PREFIX, start, end);
}

SR_32 redis_mng_delete_can_rules(redis_mng_handler_t *handler, SR_32 start, SR_32 end)
{
	return redis_mng_delete_rules(handler, CAN_PREFIX, start, end);
}
#endif

// not used at all
#if 0
SR_32 redis_mng_delete_db(redis_mng_handler_t *handler)
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
	if (redis_mng_create_action(handler, WHITE_LIST_ACTION, SR_TRUE, SR_TRUE) != SR_ERR_OK) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=sr_white_list_create_action: redis_mng_create_action failed",REASON);
                return SR_ERROR;
        }

	printf("Delete rules 0%% ...");
	redis_mng_delete_rules(handler, FILE_PREFIX, 0, SR_FILE_WL_START_RULE_NO);
	printf("\rDelete rules 33%% ...");
	redis_mng_delete_rules(handler, NET_PREFIX, 0, SR_IP_WL_START_RULE_NO);
	printf("\rDelete rules 66%% ...");
	redis_mng_delete_rules(handler, CAN_PREFIX, 0, SR_CAN_WL_START_RULE_NO);
	printf("\rDelete rules 100%% \n");

	return SR_SUCCESS;
}
#endif

// used only by cli, not needed for redis, does not create a new db and then diff with existing
#if 0
SR_32 redis_mng_delete_all(redis_mng_handler_t *handler, SR_BOOL is_commit)
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
#endif

// used to get policy from server - not needed anymore
#if 0
SR_32 redis_mng_parse_json(redis_mng_handler_t *handler, char *buf, SR_U32 *version, SR_U32 old_version)
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
			rc = redis_mng_delete_db(handler);
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
#endif

redisContext *redis_mng_session_start(void/*SR_BOOL is_tcp*/)
{ 
	redisContext *c;
	redisReply *reply;
	// choose connection type
//	if (is_tcp)
//		c = redisConnect("127.0.0.1", 6379);
//	else // unix sockets
	c = redisConnectUnix("/dev/redis.sock");
	// verify success here, else return NULL
	if (c == NULL || c->err) {
			printf("ERROR: %s failed, ret %d\n", /*is_tcp ? "redisConnect" :*/ "redisConnectUnix", c ? c->err : 0);
			return NULL;
	}
	// authenticate
	reply = redisCommand(c,"%s %s", AUTH, PASS_128);
	if (reply == NULL || reply->type != REDIS_REPLY_STATUS || strcmp(reply->str, "OK")) {
		printf("ERROR: redis_mng_session_start auth failed, %d, %s\n", reply ? reply->type : -1, reply->str ? reply->str : "NULL");
		freeReplyObject(reply);
		redisFree(c);
		return NULL;
	}
	freeReplyObject(reply);
	redis_changes = 0;
	return c;
}

void redis_mng_session_end(redisContext *c)
{
	redisFree(c);
}

#if 0
SR_U8 redis_mng_perm_get_code(char *perms)
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
#endif

void file_op_convert(SR_U8 file_op, char *perms)
{
	//SR_U8 res = 0;

	if (file_op & SR_FILEOPS_READ) 
		//res |= 4;
		sprintf(perms, "R");
	if (file_op & SR_FILEOPS_WRITE) 
		//res |= 2;
		sprintf(perms, "W");
	if (file_op & SR_FILEOPS_EXEC) 
		//res |= 1;
		sprintf(perms, "X");

	//sprintf(perms, "77%d", res);
}

#define ADD_FILE_FIELD(fieldname, fieldvalue) \
	sprintf(str_param, "%snum='%d']/%s[id='%d']/%s", FILE_PREFIX, rule_id, TUPLE, tuple, fieldname); \
        if (um_set_value(handler->sess, str_param, fieldvalue) != SR_SUCCESS) { \
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, \
                        "%s=after um_set_value str_param:%s: ", REASON, str_param); \
                return SR_ERROR; \
        }

#define ADD_NET_FIELD(tuple, fieldname, fieldvalue) \
	sprintf(str_param, "%snum='%d']/%s[id='%d']/%s", NET_PREFIX, rule_id, TUPLE, tuple, fieldname); \
        if (um_set_value(handler->sess, str_param, fieldvalue) != SR_SUCCESS) { \
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, \
                        "%s=after um_set_value str_param:%s: ", REASON, str_param); \
                return SR_ERROR; \
        }

SR_32 redis_mng_print_actions(redisContext *c)
{
	int i, j;
	redisReply *reply;
	redisReply **replies;

	// get all keys
	reply = redisCommand(c,"KEYS %s*", ACTION_PREFIX);
	if (reply == NULL || reply->type != REDIS_REPLY_ARRAY) {
		printf("ERROR: redis_mng_print_actions failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}

	replies = malloc(sizeof(redisReply*) * reply->elements);
	if (!replies) {
		printf("ERROR: redis_mng_print_actions allocation failed\n");
		freeReplyObject(reply);
		return SR_ERROR;
	}

	for (i = 0; i < reply->elements; i++)
		redisAppendCommand(c,"HGETALL %s", reply->element[i]->str);

	for (i = 0; i < (int)reply->elements; i++) {
		if (redisGetReply(c, (void*)&replies[i]) != REDIS_OK) {
			printf("ERROR: redisGetReply %d failed\n", i);
			for (j = 0; j < i; j++)
				freeReplyObject(replies[j]);
			free(replies);
			freeReplyObject(reply);
			return SR_ERROR;
		}
		if (replies[i]->type != REDIS_REPLY_ARRAY) {
			printf("ERROR: redisGetReply %d type is wrong %d\n", i, replies[i]->type);
			for (j = 0; j < i; j++)
				freeReplyObject(replies[j]);
			free(replies);
			freeReplyObject(reply);
			return SR_ERROR;
		}
		if (replies[i]->elements != ACTION_FIELDS) {
			printf("ERROR: redisGetReply %d length is wrong %d instead of 8\n", i, (int)replies[i]->elements);
			for (j = 0; j < i; j++)
				freeReplyObject(replies[j]);
			free(replies);
			freeReplyObject(reply);
			return SR_ERROR;
		}

		// action has no number so all are printed
		// ACTION_BITMAP, action->action_bm, ACTION_LOG, action->action_log, RL_BITMAP, action->rl_bm, RL_LOG, action->rl_log
		printf("%-10s %-6s %-6s %-6s %s \n",
				reply->element[i]->str + strlen(ACTION_PREFIX), /* name */
				replies[i]->element[1]->str, /* action_bm */
				replies[i]->element[3]->str, /* action_log */
				replies[i]->element[5]->str, /* rl_mb */
				replies[i]->element[7]->str /* rl_log */);
	}

	// free replies
	for (i = 0; i < reply->elements; i++)
		freeReplyObject(replies[i]);
	free(replies);
	freeReplyObject(reply);
	return SR_SUCCESS;
}

SR_32 redis_mng_print_list(redisContext *c, list_type_e type, char *name)
{
	int j;
	redisReply *reply;

	if (name) {
		// get specific key
		reply = redisCommand(c,"LRANGE %d%s%s 0 -1", type, LIST_PREFIX, name);
		if (reply == NULL || reply->type != REDIS_REPLY_ARRAY) {
			printf("ERROR: redis_mng_print_list failed, %d\n", reply ? reply->type : -1);
			freeReplyObject(reply);
			return SR_ERROR;
		}

		for (j = 0; j < reply->elements; j++)
			printf("%-64s ", reply->element[j]->str);
		printf("\n");

		freeReplyObject(reply);

	} else {
		printf("ERROR: redis_mng_print_list list name is NULL\n");
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

SR_32 redis_mng_print_all_list_names(redisContext *c, list_type_e type)
{
	int i;
	redisReply *reply;

	// get all keys
	reply = redisCommand(c,"KEYS %d%s*", type, LIST_PREFIX);
	if (reply == NULL || reply->type != REDIS_REPLY_ARRAY) {
		printf("ERROR: redis_mng_print_all_list_names failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}

	for (i = 0; i < reply->elements; i++)
		printf("%-64s ", reply->element[i]->str);
	printf("\n");

	freeReplyObject(reply);
	return SR_SUCCESS;
}

SR_32 redis_mng_print_rules(redisContext *c, rule_type_t type, SR_32 rule_id_start, SR_32 rule_id_end)
{
	int i, j, num;
	redisReply *reply;
	redisReply **replies;

	// get all keys
	reply = redisCommand(c,"KEYS %s*", type == RULE_TYPE_CAN ? CAN_PREFIX : (type == RULE_TYPE_IP ? NET_PREFIX : FILE_PREFIX));
	if (reply == NULL || reply->type != REDIS_REPLY_ARRAY) {
		printf("ERROR: redis_mng_print_rules failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}

	replies = malloc(sizeof(redisReply*) * reply->elements);
	if (!replies) {
		printf("ERROR: redis_mng_print_rules allocation failed\n");
		freeReplyObject(reply);
		return SR_ERROR;
	}

	for (i = 0; i < reply->elements; i++)
		redisAppendCommand(c,"HGETALL %s", reply->element[i]->str);

	for (i = 0; i < (int)reply->elements; i++) {
		if (redisGetReply(c, (void*)&replies[i]) != REDIS_OK) {
			printf("ERROR: redisGetReply %d failed\n", i);
			for (j = 0; j < i; j++)
				freeReplyObject(replies[j]);
			free(replies);
			freeReplyObject(reply);
			return SR_ERROR;
		}
		if (replies[i]->type != REDIS_REPLY_ARRAY) {
			printf("ERROR: redisGetReply %d type is wrong %d\n", i, replies[i]->type);
			for (j = 0; j < i; j++)
				freeReplyObject(replies[j]);
			free(replies);
			freeReplyObject(reply);
			return SR_ERROR;
		}

		if ((type == RULE_TYPE_CAN)/* && strstr(reply->element[i]->str, CAN_PREFIX)*/) { // can rule

			/*if (replies[i]->elements != CAN_RULE_FIELDS) {
				printf("ERROR: redisGetReply %d length is wrong %d instead of %d\n", i, (int)replies[i]->elements, CAN_RULE_FIELDS);
				for (j = 0; j < i; j++)
					freeReplyObject(replies[j]);
				free(replies);
				freeReplyObject(reply);
				return SR_ERROR;
			}*/

			num = atoi(reply->element[i]->str + strlen(CAN_PREFIX));
			if (((rule_id_start == -1) && (rule_id_end == -1)) || ((num >= rule_id_start) && (num <= rule_id_end))) {
					printf("\r%-6d %-8s %-24.24s %-24.24s %-24.24s %-24.24s %-24.24s\n",
							num,
							replies[i]->elements > 3 ? replies[i]->element[3]->str : "NA", /* msg_id */
							replies[i]->elements > 5 ? replies[i]->element[5]->str : "NA", /* direction */
							replies[i]->elements > 7 ? replies[i]->element[7]->str : "NA", /* interface */
							replies[i]->elements > 9 ? replies[i]->element[9]->str : "NA", /* program */
							replies[i]->elements > 11 ? replies[i]->element[11]->str : "NA", /* user */
							replies[i]->elements > 1 ? replies[i]->element[1]->str : "NA" /* action */);
			}

		} else if ((type == RULE_TYPE_IP)/* && strstr(reply->element[i]->str, NET_PREFIX)*/) { // net rule

			/*if (replies[i]->elements != NET_RULE_FIELDS) {
				printf("ERROR: redisGetReply %d length is wrong %d instead of %d\n", i, (int)replies[i]->elements, NET_RULE_FIELDS);
				for (j = 0; j < i; j++)
					freeReplyObject(replies[j]);
				free(replies);
				freeReplyObject(reply);
				return SR_ERROR;
			}*/

			num = atoi(reply->element[i]->str + strlen(NET_PREFIX));
			if (((rule_id_start == -1) && (rule_id_end == -1)) || ((num >= rule_id_start) && (num <= rule_id_end))) {
				printf("%-6d %-32s %-32s %s %s %s %-24.24s %-24.24s %-24.24s %-24.24s %-24.24s\n",
						num,
						replies[i]->elements > 3 ? replies[i]->element[3]->str : "NA", /* src_addr | src_netmask */
						replies[i]->elements > 5 ? replies[i]->element[5]->str : "NA", /* dst_addr | dst_netmask */
						replies[i]->elements > 11 ? replies[i]->element[11]->str : "NA", /* proto */
						replies[i]->elements > 13 ? replies[i]->element[13]->str : "NA", /* srcport */
						replies[i]->elements > 15 ? replies[i]->element[15]->str : "NA", /* dstport */
						replies[i]->elements > 7 ? replies[i]->element[7]->str : "NA", /*program */
						replies[i]->elements > 9 ? replies[i]->element[9]->str : "NA", /* user */
						replies[i]->elements > 1 ? replies[i]->element[1]->str : "NA", /* action */
						replies[i]->elements > 17 ? replies[i]->element[17]->str : "NA", /* up_rl */
						replies[i]->elements > 19 ? replies[i]->element[19]->str : "NA" /* down_rl */);
			}

		} else if ((type == RULE_TYPE_FILE)/* && strstr(reply->element[i]->str, FILE_PREFIX)*/) { // file rule

			/*if (replies[i]->elements != FILE_RULE_FIELDS) {
				printf("ERROR: redisGetReply %d length is wrong %d instead of %d\n", i, (int)replies[i]->elements, FILE_RULE_FIELDS);
				for (j = 0; j < i; j++)
					freeReplyObject(replies[j]);
				free(replies);
				freeReplyObject(reply);
				return SR_ERROR;
			}*/

			num = atoi(reply->element[i]->str + strlen(FILE_PREFIX));
			if (((rule_id_start == -1) && (rule_id_end == -1)) || ((num >= rule_id_start) && (num <= rule_id_end))) {
					printf("%-6d %-88.88s %-4s %-24.24s %-24.24s %-24.24s\n",
							num,
							replies[i]->elements > 3 ? replies[i]->element[3]->str : "NA", /* filename */
							replies[i]->elements > 5 ? replies[i]->element[5]->str : "NA", /* permission */
							replies[i]->elements > 7 ? replies[i]->element[7]->str : "NA", /* program */
							replies[i]->elements > 9 ? replies[i]->element[9]->str : "NA", /* user */
							replies[i]->elements > 1 ? replies[i]->element[1]->str : "NA" /* action */);
			}
		}
	}

	// free replies
	for (i = 0; i < reply->elements; i++)
		freeReplyObject(replies[i]);
	free(replies);
	freeReplyObject(reply);
	return SR_SUCCESS;
}

SR_32 redis_mng_clean_db(redisContext *c)
{
	redisReply *reply;
	reply = redisCommand(c,"FLUSHDB");
	if (reply == NULL || reply->type != REDIS_REPLY_STATUS) {
		printf("ERROR: flush db failed\n");
		freeReplyObject(reply);
		return SR_ERROR;
	}
	freeReplyObject(reply);
	return SR_SUCCESS;
}

SR_32 redis_mng_load_db(redisContext *c, int pipelined, handle_rule_f_t cb_func)
{
	int i, j;
	redisReply *reply, *reply2;
	redisReply **replies;
	can_rule_t can_rule;
	ip_rule_t net_rule;
	file_rule_t file_rule;
	action_t action;
	SR_32 rc;
	int a1, a2, a3, a4, len;

	// get all keys
	reply = redisCommand(c,"KEYS *");
	if (reply == NULL || reply->type != REDIS_REPLY_ARRAY) {
		printf("ERROR: redis_mng_load_db failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	printf("Redis has %d keys\n", (int)reply->elements);

	if (pipelined) {
		replies = malloc(sizeof(redisReply*) * reply->elements);
		if (!replies) {
			printf("ERROR: redis_mng_load_db allocation failed\n");
			freeReplyObject(reply);
			return SR_ERROR;
		}

		for (i = 0; i < reply->elements; i++)
			redisAppendCommand(c,"HGETALL %s", reply->element[i]->str);

		for (i = 0; i < (int)reply->elements; i++) {
			if (redisGetReply(c, (void*)&replies[i]) != REDIS_OK) {
				printf("ERROR: redisGetReply %d failed\n", i);
				for (j = 0; j < i; j++)
					freeReplyObject(replies[j]);
				free(replies);
				freeReplyObject(reply);
				return SR_ERROR;
			}
			if (replies[i]->type != REDIS_REPLY_ARRAY) {
				printf("ERROR: redisGetReply %d type is wrong %d\n", i, replies[i]->type);
				for (j = 0; j < i; j++)
					freeReplyObject(replies[j]);
				free(replies);
				freeReplyObject(reply);
				return SR_ERROR;
			}
			// check type and call cb func
			// todo change to new struct without tuples
			if (strstr(reply->element[i]->str, CAN_PREFIX)) { // can rule

				// ACTION, action, MID, mid, IN_INTERFACE, dir_str, OUT_INTERFACE, interface, PROGRAM_ID, exec, USER_ID, user
				if (replies[i]->elements != CAN_RULE_FIELDS) {
					printf("ERROR: redisGetReply %d length is wrong %d instead of %d\n", i, (int)replies[i]->elements,
							CAN_RULE_FIELDS);
					for (j = 0; j < i; j++)
						freeReplyObject(replies[j]);
					free(replies);
					freeReplyObject(reply);
					return SR_ERROR;
				}
				memset(&can_rule, 0, sizeof(can_rule));
				can_rule.rulenum = atoi(reply->element[i]->str + strlen(CAN_PREFIX));
				memcpy(can_rule.action_name, replies[i]->element[1]->str, strlen(replies[i]->element[1]->str));
				can_rule.tuple.id = 1; // todo remove
				can_rule.tuple.direction = atoi(replies[i]->element[5]->str);
				memcpy(can_rule.tuple.interface, replies[i]->element[7]->str, strlen(replies[i]->element[7]->str));
				can_rule.tuple.max_rate = 100; // todo add rl to can rule
				can_rule.tuple.msg_id = atoi(replies[i]->element[3]->str);
				memcpy(can_rule.tuple.program, replies[i]->element[9]->str, strlen(replies[i]->element[9]->str));
				memcpy(can_rule.tuple.user, replies[i]->element[11]->str, strlen(replies[i]->element[11]->str));

				cb_func(&can_rule, CONFIG_CAN_RULE, &rc);
				if (rc) {
					printf("ERROR: cb func failed to add CAN rule %d, ret %d\n", i, rc);
					for (j = 0; j < i; j++)
						freeReplyObject(replies[j]);
					free(replies);
					freeReplyObject(reply);
					return SR_ERROR;
				}

			} else if (strstr(reply->element[i]->str, NET_PREFIX)) { // net rule

				// ACTION, action, SRC_ADDR, src_addr_netmask, DST_ADDR, dst_addr_netmask, PROGRAM_ID, exec, USER_ID, user,
				// PROTOCOL, proto, SRC_PORT, src_port, DST_PORT, dst_port
				if (replies[i]->elements != NET_RULE_FIELDS) {
					printf("ERROR: redisGetReply %d length is wrong %d instead of %d\n", i, (int)replies[i]->elements,
							NET_RULE_FIELDS);
					for (j = 0; j < i; j++)
						freeReplyObject(replies[j]);
					free(replies);
					freeReplyObject(reply);
					return SR_ERROR;
				}
				memset(&net_rule, 0, sizeof(net_rule));
				net_rule.rulenum = atoi(reply->element[i]->str + strlen(NET_PREFIX));
				memcpy(net_rule.action_name, replies[i]->element[1]->str, strlen(replies[i]->element[1]->str));
				net_rule.tuple.id = 1; // todo remove
				sscanf(replies[i]->element[5]->str, "%d.%d.%d.%d/%d", &a1, &a2, &a3, &a4, &len);
				net_rule.tuple.dstaddr.s_addr = a1 << 24 | a2 << 16 | a3 << 8 | a4;
				net_rule.tuple.dstnetmasklen = len;
				sscanf(replies[i]->element[3]->str, "%d.%d.%d.%d/%d", &a1, &a2, &a3, &a4, &len);
				net_rule.tuple.srcaddr.s_addr = a1 << 24 | a2 << 16 | a3 << 8 | a4;
				net_rule.tuple.srcnetmasklen = len;
				net_rule.tuple.proto = atoi(replies[i]->element[11]->str);
				net_rule.tuple.srcport = atoi(replies[i]->element[13]->str);
//				if (net_rule.rulenum == 1) {
//					printf("*** DBG *** LOAD: dstport %s %s\n", replies[i]->element[14]->str, replies[i]->element[15]->str);
//					printf("*** DBG *** LOAD: srcport %s %s\n", replies[i]->element[12]->str, replies[i]->element[13]->str);
//				}
				net_rule.tuple.dstport = atoi(replies[i]->element[15]->str);
				net_rule.tuple.max_rate = 100; // todo add rl to can rule
				memcpy(net_rule.tuple.program, replies[i]->element[7]->str, strlen(replies[i]->element[7]->str));
				memcpy(net_rule.tuple.user, replies[i]->element[9]->str, strlen(replies[i]->element[9]->str));

				cb_func(&net_rule, CONFIG_NET_RULE, &rc);
				if (rc) {
					printf("ERROR: cb func failed to add net rule %d, ret %d\n", i, rc);
					for (j = 0; j < i; j++)
						freeReplyObject(replies[j]);
					free(replies);
					freeReplyObject(reply);
					return SR_ERROR;
				}

			} else if (strstr(reply->element[i]->str, FILE_PREFIX)) { // file rule

				// ACTION, action, FILENAME, file_name, PERMISSION, perms, PROGRAM_ID, exec, USER_ID, user
				if (replies[i]->elements != FILE_RULE_FIELDS) {
					printf("ERROR: redisGetReply %d length is wrong %d instead of %d\n", i, (int)replies[i]->elements, FILE_RULE_FIELDS);
					for (j = 0; j < i; j++)
						freeReplyObject(replies[j]);
					free(replies);
					freeReplyObject(reply);
					return SR_ERROR;
				}
				memset(&file_rule, 0, sizeof(file_rule));
				file_rule.rulenum = atoi(reply->element[i]->str + strlen(FILE_PREFIX));
				memcpy(file_rule.action_name, replies[i]->element[1]->str, strlen(replies[i]->element[1]->str));
				file_rule.tuple.id = 1; // todo remove
				memcpy(file_rule.tuple.filename ,replies[i]->element[3]->str, strlen(replies[i]->element[3]->str));
				file_rule.tuple.max_rate = 100; // todo add rl to can rule
				memcpy(file_rule.tuple.permission, replies[i]->element[5]->str, strlen(replies[i]->element[5]->str));
				memcpy(file_rule.tuple.program, replies[i]->element[7]->str, strlen(replies[i]->element[7]->str));
				memcpy(file_rule.tuple.user, replies[i]->element[9]->str, strlen(replies[i]->element[9]->str));

				cb_func(&file_rule, CONFIG_FILE_RULE, &rc);
				if (rc) {
					printf("ERROR: cb func failed to add file rule %d, ret %d\n", i, rc);
					for (j = 0; j < i; j++)
						freeReplyObject(replies[j]);
					free(replies);
					freeReplyObject(reply);
					return SR_ERROR;
				}

			} else { // action

				// BITMAP, bm, LOG_FACILITY, log_facility, LOG_SEVERITY, log_severity, RL, rl, SMS, sms, EMAIL, mail
				if (replies[i]->elements != ACTION_FIELDS) {
					printf("ERROR: redisGetReply %d length is wrong %d instead of %d\n", i, (int)replies[i]->elements, ACTION_FIELDS);
					for (j = 0; j < i; j++)
						freeReplyObject(replies[j]);
					free(replies);
					freeReplyObject(reply);
					return SR_ERROR;
				}
				action.black_list = 0; // fixme
				action.terminate = 0; // fixme
				// todo replies[i]->element[7]->str - rate limit
				memcpy(action.action_name, reply->element[i]->str + strlen(ACTION_PREFIX),
						strlen(reply->element[i]->str) - strlen(ACTION_PREFIX));

				if (strstr(replies[i]->element[1]->str, "drop"))
					action.action = ACTION_DROP;
				else if (strstr(replies[i]->element[1]->str, "none"))
					action.action = ACTION_NONE;
				else if (strstr(replies[i]->element[1]->str, "allow"))
					action.action = ACTION_ALLOW;
				else
					action.action = ACTION_INVALID;

				if (strstr(replies[i]->element[3]->str, "file"))
					action.log_facility = LOG_TO_FILE;
				else if (strstr(replies[i]->element[3]->str, "none"))
					action.log_facility = LOG_NONE;
				else if (strstr(replies[i]->element[3]->str, "sys"))
					action.log_facility = LOG_TO_SYSLOG;
				else
					action.log_facility = LOG_INVALID;

				if (strstr(replies[i]->element[5]->str, "crt"))
					action.log_severity = LOG_SEVERITY_CRT;
				else if (strstr(replies[i]->element[5]->str, "err"))
					action.log_severity = LOG_SEVERITY_ERR;
				else if (strstr(replies[i]->element[5]->str, "warn"))
					action.log_severity = LOG_SEVERITY_WARN;
				else if (strstr(replies[i]->element[5]->str, "info"))
					action.log_severity = LOG_SEVERITY_INFO;
				else if (strstr(replies[i]->element[5]->str, "debug"))
					action.log_severity = LOG_SEVERITY_DEBUG;
				else
					action.log_severity = LOG_SEVERITY_NONE;

				cb_func(&action, CONFIG_LOG_TARGET, &rc);
				if (rc) {
					printf("ERROR: cb func failed to add action %d, ret %d\n", i, rc);
					for (j = 0; j < i; j++)
						freeReplyObject(replies[j]);
					free(replies);
					freeReplyObject(reply);
					return SR_ERROR;
				}
			}
		}

		// free replies
		for (i = 0; i < reply->elements; i++)
			freeReplyObject(replies[i]);
		free(replies);

	} else {
		// same NOT pipelined

		for (i = 0; i < reply->elements; i++) {
			reply2 = redisCommand(c,"HGETALL %s", reply->element[i]->str);
			if (reply2 == NULL || reply2->type != REDIS_REPLY_ARRAY) {
				printf("ERROR: redis_mng_load_db failed, %d\n", reply2 ? reply2->type : -1);
				freeReplyObject(reply);
				if (reply2)
					freeReplyObject(reply2);
				return SR_ERROR;
			}

			// check type and call cb func
			// todo change to new struct without tuples
			if (strstr(reply->element[i]->str, CAN_PREFIX)) { // can rule

				// ACTION, action, MID, mid, IN_INTERFACE, dir_str, OUT_INTERFACE, interface, PROGRAM_ID, exec, USER_ID, user
				if (reply2->elements != CAN_RULE_FIELDS) {
					printf("ERROR: redisGetReply %d length is wrong %d instead of %d\n", i, (int)reply2->elements, CAN_RULE_FIELDS);
					freeReplyObject(reply);
					freeReplyObject(reply2);
					return SR_ERROR;
				}
				memset(&can_rule, 0, sizeof(can_rule));
				can_rule.rulenum = atoi(reply->element[i]->str + strlen(CAN_PREFIX));
				memcpy(can_rule.action_name, reply2->element[1]->str, strlen(reply2->element[1]->str));
				can_rule.tuple.id = 1; // todo remove
				can_rule.tuple.direction = atoi(reply2->element[5]->str);
				memcpy(can_rule.tuple.interface, reply2->element[7]->str, strlen(reply2->element[7]->str));
				can_rule.tuple.max_rate = 100; // todo add rl to can rule
				can_rule.tuple.msg_id = atoi(reply2->element[3]->str);
				memcpy(can_rule.tuple.program, reply2->element[9]->str, strlen(reply2->element[9]->str));
				memcpy(can_rule.tuple.user, reply2->element[11]->str, strlen(reply2->element[11]->str));

				cb_func(&can_rule, CONFIG_CAN_RULE, &rc);
				if (rc) {
					printf("ERROR: cb func failed to add CAN rule %d, ret %d\n", i, rc);
					freeReplyObject(reply);
					freeReplyObject(reply2);
					return SR_ERROR;
				}

			} else if (strstr(reply->element[i]->str, NET_PREFIX)) { // net rule

				// ACTION, action, SRC_ADDR, src_addr_netmask, DST_ADDR, dst_addr_netmask, PROGRAM_ID, exec, USER_ID, user,
				// PROTOCOL, proto, SRC_PORT, src_port, DST_PORT, dst_port
				if (reply2->elements != NET_RULE_FIELDS) {
					printf("ERROR: redisGetReply %d length is wrong %d instead of %d\n", i, (int)reply2->elements, NET_RULE_FIELDS);
					freeReplyObject(reply);
					freeReplyObject(reply2);
					return SR_ERROR;
				}

				memset(&net_rule, 0, sizeof(net_rule));
				net_rule.rulenum = atoi(reply->element[i]->str + strlen(NET_PREFIX));
				memcpy(net_rule.action_name, reply2->element[1]->str, strlen(reply2->element[1]->str));
				net_rule.tuple.id = 1; // todo remove
				sscanf(reply2->element[5]->str, "%d.%d.%d.%d/%d", &a1, &a2, &a3, &a4, &len);
				net_rule.tuple.dstaddr.s_addr = a1 << 24 | a2 << 16 | a3 << 8 | a4;
				net_rule.tuple.dstnetmasklen = len;
				sscanf(reply2->element[3]->str, "%d.%d.%d.%d/%d", &a1, &a2, &a3, &a4, &len);
				net_rule.tuple.srcaddr.s_addr = a1 << 24 | a2 << 16 | a3 << 8 | a4;
				net_rule.tuple.srcnetmasklen = len;
				net_rule.tuple.proto = atoi(reply2->element[11]->str);
				net_rule.tuple.srcport = atoi(reply2->element[13]->str);
				net_rule.tuple.dstport = atoi(reply2->element[15]->str);
				net_rule.tuple.max_rate = 100; // todo add rl to can rule
				memcpy(net_rule.tuple.program, reply2->element[7]->str, strlen(reply2->element[7]->str));
				memcpy(net_rule.tuple.user, reply2->element[9]->str, strlen(reply2->element[9]->str));

				cb_func(&net_rule, CONFIG_NET_RULE, &rc);
				if (rc) {
					printf("ERROR: cb func failed to add net rule %d, ret %d\n", i, rc);
					freeReplyObject(reply);
					freeReplyObject(reply2);
					return SR_ERROR;
				}

			} else if (strstr(reply->element[i]->str, FILE_PREFIX)) { // file rule

				// ACTION, action, FILENAME, file_name, PERMISSION, perms, PROGRAM_ID, exec, USER_ID, user
				if (reply2->elements != FILE_RULE_FIELDS) {
					printf("ERROR: redisGetReply %d length is wrong %d instead of %d\n", i, (int)reply2->elements, FILE_RULE_FIELDS);
					freeReplyObject(reply);
					freeReplyObject(reply2);
					return SR_ERROR;
				}
				memset(&file_rule, 0, sizeof(file_rule));
				file_rule.rulenum = atoi(reply->element[i]->str + strlen(FILE_PREFIX));
				memcpy(file_rule.action_name, reply2->element[1]->str, strlen(reply2->element[1]->str));
				file_rule.tuple.id = 1; // todo remove
				memcpy(file_rule.tuple.filename ,reply2->element[3]->str, strlen(reply2->element[3]->str));
				file_rule.tuple.max_rate = 100; // todo add rl to can rule
				memcpy(file_rule.tuple.permission, reply2->element[5]->str, strlen(reply2->element[5]->str));
				memcpy(file_rule.tuple.program, reply2->element[7]->str, strlen(reply2->element[7]->str));
				memcpy(file_rule.tuple.user, reply2->element[9]->str, strlen(reply2->element[9]->str));

				cb_func(&file_rule, CONFIG_FILE_RULE, &rc);
				if (rc) {
					printf("ERROR: cb func failed to add file rule %d, ret %d\n", i, rc);
					freeReplyObject(reply);
					freeReplyObject(reply2);
					return SR_ERROR;
				}
			} else { // action

				// BITMAP, bm, LOG, log, SMS, sms, EMAIL, mail
				if (reply2->elements != ACTION_FIELDS) {
					printf("ERROR: redisGetReply %d length is wrong %d instead of %d\n", i, (int)reply2->elements, ACTION_FIELDS);
					freeReplyObject(reply);
					freeReplyObject(reply2);
					return SR_ERROR;
				}
				action.black_list = 0; // fixme
				action.terminate = 0; // fixme
				memcpy(action.action_name, reply->element[i]->str + strlen(ACTION_PREFIX),
						strlen(reply->element[i]->str) - strlen(ACTION_PREFIX));

				if (strstr(reply2->element[1]->str, "drop"))
					action.action = ACTION_DROP;
				else if (strstr(reply2->element[1]->str, "none"))
					action.action = ACTION_NONE;
				else if (strstr(reply2->element[1]->str, "allow"))
					action.action = ACTION_ALLOW;
				else
					action.action = ACTION_INVALID;

				if (strstr(reply2->element[3]->str, "file"))
					action.log_facility = LOG_TO_FILE;
				else if (strstr(reply2->element[3]->str, "none"))
					action.log_facility = LOG_NONE;
				else if (strstr(reply2->element[3]->str, "sys"))
					action.log_facility = LOG_TO_SYSLOG;
				else
					action.log_facility = LOG_INVALID;

				if (strstr(reply2->element[3]->str, "crt"))
					action.log_severity = LOG_SEVERITY_CRT;
				else if (strstr(reply2->element[3]->str, "err"))
					action.log_severity = LOG_SEVERITY_ERR;
				else if (strstr(reply2->element[3]->str, "warn"))
					action.log_severity = LOG_SEVERITY_WARN;
				else if (strstr(reply2->element[3]->str, "info"))
					action.log_severity = LOG_SEVERITY_INFO;
				else if (strstr(reply2->element[3]->str, "debug"))
					action.log_severity = LOG_SEVERITY_DEBUG;
				else
					action.log_severity = LOG_SEVERITY_NONE;

				cb_func(&action, CONFIG_LOG_TARGET, &rc);
				if (rc) {
					printf("ERROR: cb func failed to add action %d, ret %d\n", i, rc);
					freeReplyObject(reply);
					freeReplyObject(reply2);
					return SR_ERROR;
				}
			}

			freeReplyObject(reply2);
		}
	}

	freeReplyObject(reply);
	return SR_SUCCESS;
}

#if 0
SR_32 redis_mng_reconf(redisContext *c, handle_rule_f_t cb_func)
{
	int i, j;
	redisReply *reply;
	redisReply **replies;
	can_rule_t can_rule;
	ip_rule_t net_rule;
	file_rule_t file_rule;
	SR_32 rc;

	// get all keys
	reply = redisCommand(c,"KEYS *");
	if (reply == NULL || reply->type != REDIS_REPLY_ARRAY) {
		printf("ERROR: redis_mng_reconf failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}

	replies = malloc(sizeof(redisReply*) * reply->elements);
	if (!replies) {
		printf("ERROR: redis_mng_reconf allocation failed\n");
		freeReplyObject(reply);
		return SR_ERROR;
	}


	for (i = 0; i < reply->elements; i++)
		redisAppendCommand(c,"HGETALL %s", reply->element[i]->str);

	for (i = 0; i < (int)reply->elements; i++) {
		if (redisGetReply(c, (void*)&replies[i]) != REDIS_OK) {
			printf("ERROR: redisGetReply %d failed\n", i);
			for (j = 0; j < i; j++)
				freeReplyObject(replies[j]);
			free(replies);
			freeReplyObject(reply);
			return SR_ERROR;
		}
		if (replies[i]->type != REDIS_REPLY_ARRAY) {
			printf("ERROR: redisGetReply %d type is wrong %d\n", i, replies[i]->type);
			for (j = 0; j < i; j++)
				freeReplyObject(replies[j]);
			free(replies);
			freeReplyObject(reply);
			return SR_ERROR;
		}
		// check type and call cb func
		// todo change to new struct without tuples
		if (strstr(reply->element[i]->str, CAN_PREFIX)) { // can rule

			// ACTION, action, MID, mid, IN_INTERFACE, dir_str, OUT_INTERFACE, interface, PROGRAM_ID, exec, USER_ID, user
			if (replies[i]->elements != CAN_RULE_FIELDS) {
				printf("ERROR: redisGetReply %d length is wrong %d instead of %d\n", i, (int)replies[i]->elements, CAN_RULE_FIELDS);
				for (j = 0; j < i; j++)
					freeReplyObject(replies[j]);
				free(replies);
				freeReplyObject(reply);
				return SR_ERROR;
			}
			memset(&can_rule, 0, sizeof(can_rule));
			can_rule.rulenum = atoi(reply->element[i]->str + strlen(CAN_PREFIX));
			memcpy(can_rule.action_name, replies[i]->element[1]->str, strlen(replies[i]->element[1]->str));
			can_rule.tuple.id = 1; // todo remove
			can_rule.tuple.direction = atoi(replies[i]->element[5]->str);
			memcpy(can_rule.tuple.interface, replies[i]->element[7]->str, strlen(replies[i]->element[7]->str));
			can_rule.tuple.max_rate = 100; // todo add rl to can rule
			can_rule.tuple.msg_id = atoi(replies[i]->element[3]->str);
			memcpy(can_rule.tuple.program, replies[i]->element[9]->str, strlen(replies[i]->element[9]->str));
			memcpy(can_rule.tuple.user, replies[i]->element[11]->str, strlen(replies[i]->element[11]->str));

			cb_func(&can_rule, CONFIG_CAN_RULE, &rc);
			if (rc) {
				printf("ERROR: cb func failed to add CAN rule %d, ret %d\n", i, rc);
				for (j = 0; j < i; j++)
					freeReplyObject(replies[j]);
				free(replies);
				freeReplyObject(reply);
				return SR_ERROR;
			}

		} else if (strstr(reply->element[i]->str, NET_PREFIX)) { // net rule

			// ACTION, action, SRC_ADDR, src_addr_netmask, DST_ADDR, dst_addr_netmask, PROGRAM_ID, exec, USER_ID, user,
			// PROTOCOL, proto, SRC_PORT, src_port, DST_PORT, dst_port
			if (replies[i]->elements != NET_RULE_FIELDS) {
				printf("ERROR: redisGetReply %d length is wrong %d instead of %d\n", i, (int)replies[i]->elements, NET_RULE_FIELDS);
				for (j = 0; j < i; j++)
					freeReplyObject(replies[j]);
				free(replies);
				freeReplyObject(reply);
				return SR_ERROR;
			}
			memset(&net_rule, 0, sizeof(net_rule));
			net_rule.rulenum = atoi(reply->element[i]->str + strlen(NET_PREFIX));
			memcpy(net_rule.action_name, replies[i]->element[1]->str, strlen(replies[i]->element[1]->str));
			net_rule.tuple.id = 1; // todo remove
			sscanf(replies[i]->element[5]->str, "%d.%d.%d.%d/%d", &a1, &a2, &a3, &a4, &len);
			net_rule.tuple.dstaddr.s_addr = a1 << 24 | a2 << 16 | a3 << 8 | a4;
			net_rule.tuple.dstnetmasklen = len;
			sscanf(replies[i]->element[3]->str, "%d.%d.%d.%d/%d", &a1, &a2, &a3, &a4, &len);
			net_rule.tuple.srcaddr.s_addr = a1 << 24 | a2 << 16 | a3 << 8 | a4;
			net_rule.tuple.srcnetmasklen = len;
			net_rule.tuple.proto = atoi(replies[i]->element[11]->str);
			net_rule.tuple.srcport = atoi(replies[i]->element[13]->str);
			net_rule.tuple.dstport = atoi(replies[i]->element[15]->str);
			net_rule.tuple.max_rate = 100; // todo add rl to can rule
			memcpy(net_rule.tuple.program, replies[i]->element[7]->str, strlen(replies[i]->element[7]->str));
			memcpy(net_rule.tuple.user, replies[i]->element[9]->str, strlen(replies[i]->element[9]->str));

			cb_func(&net_rule, CONFIG_NET_RULE, &rc);
			if (rc) {
				printf("ERROR: cb func failed to add net rule %d, ret %d\n", i, rc);
				for (j = 0; j < i; j++)
					freeReplyObject(replies[j]);
				free(replies);
				freeReplyObject(reply);
				return SR_ERROR;
			}

		} else if (strstr(reply->element[i]->str, FILE_PREFIX)) { // file rule

			// ACTION, action, FILENAME, file_name, PERMISSION, perms, PROGRAM_ID, exec, USER_ID, user
			if (replies[i]->elements != FILE_RULE_FIELDS) {
				printf("ERROR: redisGetReply %d length is wrong %d instead of %d\n", i, (int)replies[i]->elements, FILE_RULE_FIELDS);
				for (j = 0; j < i; j++)
					freeReplyObject(replies[j]);
				free(replies);
				freeReplyObject(reply);
				return SR_ERROR;
			}
			memset(&file_rule, 0, sizeof(file_rule));
			file_rule.rulenum = atoi(reply->element[i]->str + strlen(FILE_PREFIX));
			memcpy(file_rule.action_name, replies[i]->element[1]->str, strlen(replies[i]->element[1]->str));
			file_rule.tuple.id = 1; // todo remove
			memcpy(file_rule.tuple.filename ,replies[i]->element[3]->str, strlen(replies[i]->element[3]->str));
			file_rule.tuple.max_rate = 100; // todo add rl to can rule
			memcpy(file_rule.tuple.permission, replies[i]->element[5]->str, strlen(replies[i]->element[5]->str));
			memcpy(file_rule.tuple.program, replies[i]->element[7]->str, strlen(replies[i]->element[7]->str));
			memcpy(file_rule.tuple.user, replies[i]->element[9]->str, strlen(replies[i]->element[9]->str));

			cb_func(&file_rule, CONFIG_FILE_RULE, &rc);
			if (rc) {
				printf("ERROR: cb func failed to add file rule %d, ret %d\n", i, rc);
				for (j = 0; j < i; j++)
					freeReplyObject(replies[j]);
				free(replies);
				freeReplyObject(reply);
				return SR_ERROR;
			}

		}
	}

	// free replies
	for (i = 0; i < reply->elements; i++)
		freeReplyObject(replies[i]);
	free(replies);
	freeReplyObject(reply);
	return SR_SUCCESS;
}
#endif

SR_32 redis_mng_add_action(redisContext *c, char *name, redis_mng_action_t *action)
{
    redisReply *reply;

	reply = redisCommand(c,"HMSET %s%s %s %s %s %s %s %s %s %s", ACTION_PREFIX, name,
			ACTION_BITMAP, action->action_bm ? action->action_bm : "NULL",
			ACTION_LOG, action->action_log ? action->action_log : "NULL",
			RL_BITMAP, action->rl_bm ? action->rl_bm : "NULL", RL_LOG, action->rl_log ? action->rl_log : "NULL");
	if (reply == NULL || reply->type != REDIS_REPLY_STATUS) {
		printf("ERROR: redis_mng_add_file_rule failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	freeReplyObject(reply);
	return SR_SUCCESS;
}

SR_32 redis_mng_del_action(redisContext *c, char *name)
{
    redisReply *reply;

	reply = redisCommand(c,"%s %s%s", DEL, ACTION_PREFIX, name);
	if (reply == NULL || reply->type != REDIS_REPLY_INTEGER || reply->integer != 1) {
		printf("ERROR: redis_mng_del_file_rule failed, type %d, i %d\n", reply ? reply->type : -1, reply ? (int)reply->integer : 0);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	freeReplyObject(reply);
	return SR_SUCCESS;
}

SR_32 redis_mng_add_list(redisContext *c, list_type_e type, char *name, SR_U32 length, char **values)
{
	redisReply *reply;
	int i, len = 0;
	char *cmd;

	if (length < 1) {
		printf("ERROR: redis_mng_add_list failed, invalid length %d\n", length);
		return SR_ERROR;
	}
	cmd = malloc(length * MAX_LIST_VAL_LEN);
	if (!cmd) {
		printf("ERROR: redis_mng_add_list failed, allocation failed\n");
		return SR_ERROR;
	}
	for (i = 0; i < length; i++)
		len += sprintf(cmd + len, " %s", values[i]);

	reply = redisCommand(c,"LPUSH %d%s%s %s", type, LIST_PREFIX, name, cmd);
	free(cmd);
	if (reply == NULL || reply->type != REDIS_REPLY_INTEGER || reply->integer != 1) {
		printf("ERROR: redis_mng_add_list failed, type %d, i %d\n", reply ? reply->type : -1, reply ? (int)reply->integer : 0);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	freeReplyObject(reply);
	return SR_SUCCESS;
}

SR_32 redis_mng_del_list(redisContext *c, list_type_e type, char *name, SR_U32 length, char **values)
{
	redisReply *reply;
	int i;

	if (length < 1) {
		printf("ERROR: redis_mng_del_list failed, invalid length %d\n", length);
		return SR_ERROR;
	}
	for (i = 0; i < length; i++) {
		reply = redisCommand(c,"LREM %d%s%s 0 %s", type, LIST_PREFIX, name, values[i]);
		if (reply == NULL || reply->type != REDIS_REPLY_INTEGER || reply->integer != 1) {
			printf("ERROR: redis_mng_del_list % d failed, type %d, i %d\n", i,
					reply ? reply->type : -1, reply ? (int)reply->integer : 0);
			freeReplyObject(reply);
			return SR_ERROR;
		}
		freeReplyObject(reply);
	}
	return SR_SUCCESS;
}

SR_32 redis_mng_destroy_list(redisContext *c, list_type_e type, char *name)
{
	redisReply *reply;

	reply = redisCommand(c,"%s %d%s%s", DEL, type, LIST_PREFIX, name);
	if (reply == NULL || reply->type != REDIS_REPLY_INTEGER || reply->integer != 1) {
		printf("ERROR: redis_mng_destroy_list failed, type %d, i %d\n", reply ? reply->type : -1, reply ? (int)reply->integer : 0);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	freeReplyObject(reply);
	return SR_SUCCESS;
}

SR_32 redis_mng_update_file_rule(redisContext *c, SR_32 rule_id, redis_mng_file_rule_t *rule)
{
	redisReply *reply;
	char *cmd;
	int len;

	cmd = malloc(FILE_RULE_FIELDS * MAX_LIST_NAME_LEN);
	if (!cmd) {
		printf("ERROR: redis_mng_update_file_rule allocation failed\n");
		return SR_ERROR;
	}

	len = sprintf(cmd, "HMSET %s%d", FILE_PREFIX, rule_id);
	if (rule->action)
		len += sprintf(cmd + len, " %s %s", ACTION, rule->action);
	if (rule->file_name) {
		if (rule->file_names_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", FILENAME, LIST_FILES, LIST_PREFIX, rule->file_name);
		else // single value
			len += sprintf(cmd + len, " %s %s", FILENAME, rule->file_name);
	}
	if (rule->file_op)
		len += sprintf(cmd + len, " %s %s", PERMISSION, rule->file_op);
	if (rule->exec) {
		if (rule->execs_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", PROGRAM_ID, LIST_PROGRAMS, LIST_PREFIX, rule->exec);
		else // single value
			len += sprintf(cmd + len, " %s %s", PROGRAM_ID, rule->exec);
	}
	if (rule->user) {
		if (rule->users_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", USER_ID, LIST_USERS, LIST_PREFIX, rule->user);
		else // single value
			len += sprintf(cmd + len, " %s %s", USER_ID, rule->user);
	}

	reply = redisCommand(c, cmd);
	free(cmd);
	if (reply == NULL || reply->type != REDIS_REPLY_STATUS) {
		printf("ERROR: redis_mng_update_file_rule failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	freeReplyObject(reply);
	return SR_SUCCESS;
}

SR_32 redis_mng_del_file_rule(redisContext *c, SR_32 rule_id_start, SR_32 rule_id_end, SR_8 force)
{
    redisReply *reply;
    SR_32 rule_id;

    for (rule_id = rule_id_start; rule_id <= rule_id_end; rule_id++) {
    	reply = redisCommand(c,"%s %s%d", DEL, FILE_PREFIX, rule_id);
    	if (!force && (reply == NULL || reply->type != REDIS_REPLY_INTEGER || reply->integer != 1)) {
    		printf("ERROR: redis_mng_del_file_rule failed, type %d, i %d\n", reply ? reply->type : -1, reply ? (int)reply->integer : 0);
    		freeReplyObject(reply);
    		return SR_ERROR;
    	}
    	freeReplyObject(reply);
    }
	return SR_SUCCESS;
}

#if 0
SR_32 redis_mng_get_file_rule(redisContext *c, SR_32 rule_id, redis_mng_reply_t *my_reply)
{
	int i;
	redisReply *reply;

	reply = redisCommand(c,"HGETALL %s%d", FILE_PREFIX, rule_id);
	if (reply == NULL || reply->type != REDIS_REPLY_ARRAY) {
		printf("ERROR: redis_mng_get_file_rule %d failed, %d\n", rule_id, reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	if (reply->elements != FILE_RULE_FIELDS) {
		printf("ERROR: redis_mng_get_file_rule %d length is wrong %d instead of %d\n", rule_id, (int)reply->elements, FILE_RULE_FIELDS);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	my_reply->num_fields = 10;
	for (i = 0; i < reply->elements; i++)
		memcpy(my_reply->feilds[i], reply->element[i]->str, strlen(reply->element[i]->str));

	freeReplyObject(reply);
	return SR_SUCCESS;
}
#endif

#if 0
SR_32 redis_mng_create_file_rule(redisContext *c, SR_32 rule_id, char *file_name, char *exec, char *user, char *action, SR_U8 file_op)
{
	char perms[4];

	file_op_convert(file_op, perms);
	redisAppendCommand(c,"HMSET %s%d %s %s %s %s %s %s %s %s %s %s %s %s", FILE_PREFIX, rule_id, ACTION, action,
			FILENAME, file_name, PERMISSION, perms, PROGRAM_ID, exec, USER_ID, user);
	redis_changes++;
	return SR_SUCCESS;
}
#endif

SR_32 redis_mng_update_net_rule(redisContext *c, SR_32 rule_id, redis_mng_net_rule_t *rule)
{
	redisReply *reply;
	char *cmd;
	int len;

	cmd = malloc(NET_RULE_FIELDS * MAX_LIST_NAME_LEN);
	if (!cmd) {
		printf("ERROR: redis_mng_update_net_rule allocation failed\n");
		return SR_ERROR;
	}

	len = sprintf(cmd, "HMSET %s%d", NET_PREFIX, rule_id);
	if (rule->action)
		len += sprintf(cmd + len, " %s %s", ACTION, rule->action);
	if (rule->src_addr_netmask) {
		if (rule->src_addr_netmasks_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", SRC_ADDR, LIST_ADDRS, LIST_PREFIX, rule->src_addr_netmask);
		else // single value
			len += sprintf(cmd + len, " %s %s", SRC_ADDR, rule->src_addr_netmask);
	}
	if (rule->dst_addr_netmask) {
		if (rule->dst_addr_netmasks_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", DST_ADDR, LIST_ADDRS, LIST_PREFIX, rule->dst_addr_netmask);
		else // single value
			len += sprintf(cmd + len, " %s %s", DST_ADDR, rule->dst_addr_netmask);
	}
	if (rule->exec) {
		if (rule->execs_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", PROGRAM_ID, LIST_PROGRAMS, LIST_PREFIX, rule->exec);
		else // single value
			len += sprintf(cmd + len, " %s %s", PROGRAM_ID, rule->exec);
	}
	if (rule->user) {
		if (rule->users_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", USER_ID, LIST_USERS, LIST_PREFIX, rule->user);
		else // single value
			len += sprintf(cmd + len, " %s %s", USER_ID, rule->user);
	}
	if (rule->proto) {
		if (rule->protos_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", PROTOCOL, LIST_PROTOCOLS, LIST_PREFIX, rule->proto);
		else // single value
			len += sprintf(cmd + len, " %s %s", PROTOCOL, rule->proto);
	}
	if (rule->src_port) {
		if (rule->src_ports_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", SRC_PORT, LIST_PORTS, LIST_PREFIX, rule->src_port);
		else // single value
			len += sprintf(cmd + len, " %s %s", SRC_PORT, rule->src_port);
	}
	if (rule->dst_port) {
		if (rule->dst_ports_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", DST_PORT, LIST_PORTS, LIST_PREFIX, rule->dst_port);
		else // single value
			len += sprintf(cmd + len, " %s %s", DST_PORT, rule->dst_port);
	}
	if (rule->action)
		len += sprintf(cmd + len, " %s %s", UP_RL, rule->action);
	if (rule->action)
		len += sprintf(cmd + len, " %s %s", DOWN_RL, rule->action);

	reply = redisCommand(c, cmd);
	free(cmd);
	if (reply == NULL || reply->type != REDIS_REPLY_STATUS) {
		printf("ERROR: redis_mng_update_net_rule failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	freeReplyObject(reply);
	return SR_SUCCESS;
}

SR_32 redis_mng_del_net_rule(redisContext *c, SR_32 rule_id_start, SR_32 rule_id_end, SR_8 force)
{
    redisReply *reply;
    SR_32 rule_id;

    for (rule_id = rule_id_start; rule_id <= rule_id_end; rule_id++) {
    	reply = redisCommand(c,"%s %s%d", DEL, NET_PREFIX, rule_id);
    	if (!force && (reply == NULL || reply->type != REDIS_REPLY_INTEGER || reply->integer != 1)) {
    		printf("ERROR: redis_mng_del_net_rule failed, type %d, i %d\n", reply ? reply->type : -1, reply ? (int)reply->integer : 0);
    		freeReplyObject(reply);
    		return SR_ERROR;
    	}
    	freeReplyObject(reply);
    }
	return SR_SUCCESS;
}

#if 0
SR_32 redis_mng_create_net_rule(redisContext *c, SR_32 rule_id, char *src_addr, char *src_netmask,
	char *dst_addr, char *dst_netmask, SR_U8 ip_proto, SR_U16 src_port, SR_U16 dst_port, char *exec, char *user, char *action)
{
	redisAppendCommand(c,"HMSET %s%d %s %s %s %s/%d %s %s/%d %s %s %s %s %s %d %s %d %s %d", NET_PREFIX, rule_id, ACTION, action,
			SRC_ADDR, src_addr, src_netmask, DST_ADDR, dst_addr, dst_netmask, PROGRAM_ID, exec, USER_ID, user,
			PROTOCOL, ip_proto, SRC_PORT, src_port, DST_PORT, dst_port);
	redis_changes++;
	return SR_SUCCESS;
}
#endif

SR_32 redis_mng_update_can_rule(redisContext *c, SR_32 rule_id, redis_mng_can_rule_t *rule)
{
	redisReply *reply;
	char *cmd;
	int len;

	cmd = malloc(CAN_RULE_FIELDS * MAX_LIST_NAME_LEN);
	if (!cmd) {
		printf("ERROR: redis_mng_update_can_rule allocation failed\n");
		return SR_ERROR;
	}

	len = sprintf(cmd, "HMSET %s%d", CAN_PREFIX, rule_id);
	if (rule->action)
		len += sprintf(cmd + len, " %s %s", ACTION, rule->action);
	if (rule->mid) {
		if (rule->mids_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", MID, LIST_MIDS, LIST_PREFIX, rule->mid);
		else // single value
			len += sprintf(cmd + len, " %s %s", MID, rule->mid);
	}
	if (rule->dir)
		len += sprintf(cmd + len, " %s %s", IN_INTERFACE, rule->dir);
	if (rule->interface) {
		if (rule->interfaces_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", OUT_INTERFACE, LIST_CAN_INTF, LIST_PREFIX, rule->interface);
		else // single value
			len += sprintf(cmd + len, " %s %s", OUT_INTERFACE, rule->interface);
	}
	if (rule->exec) {
		if (rule->execs_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", PROGRAM_ID, LIST_PROGRAMS, LIST_PREFIX, rule->exec);
		else // single value
			len += sprintf(cmd + len, " %s %s", PROGRAM_ID, rule->exec);
	}
	if (rule->user) {
		if (rule->users_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", USER_ID, LIST_USERS, LIST_PREFIX, rule->user);
		else // single value
			len += sprintf(cmd + len, " %s %s", USER_ID, rule->user);
	}

	reply = redisCommand(c, cmd);
	free(cmd);
	if (reply == NULL || reply->type != REDIS_REPLY_STATUS) {
		printf("ERROR: redis_mng_update_can_rule failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	freeReplyObject(reply);
	return SR_SUCCESS;
}

SR_32 redis_mng_del_can_rule(redisContext *c, SR_32 rule_id_start, SR_32 rule_id_end, SR_8 force)
{
    redisReply *reply;
    SR_32 rule_id;

    for (rule_id = rule_id_start; rule_id <= rule_id_end; rule_id++) {
    	reply = redisCommand(c,"%s %s%d", DEL, CAN_PREFIX, rule_id);
    	if (!force && (reply == NULL || reply->type != REDIS_REPLY_INTEGER || reply->integer != 1)) {
    		printf("ERROR: redis_mng_del_can_rule failed, type %d, i %d\n", reply ? reply->type : -1, reply ? (int)reply->integer : 0);
    		freeReplyObject(reply);
    		return SR_ERROR;
    	}
    	freeReplyObject(reply);
    }
	return SR_SUCCESS;
}

SR_32 redis_mng_has_file_rule(redisContext *c, SR_32 rule_id)
{
    redisReply *reply;
    SR_32 ret;

	reply = redisCommand(c,"EXISTS %s%d", FILE_PREFIX, rule_id);
	if (reply == NULL || reply->type != REDIS_REPLY_INTEGER) {
		printf("ERROR: redis_mng_has_file_rule failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	ret = reply->integer;
	freeReplyObject(reply);
	return ret;
}

SR_32 redis_mng_has_net_rule(redisContext *c, SR_32 rule_id)
{
    redisReply *reply;
    SR_32 ret;

	reply = redisCommand(c,"EXISTS %s%d", NET_PREFIX, rule_id);
	if (reply == NULL || reply->type != REDIS_REPLY_INTEGER) {
		printf("ERROR: redis_mng_has_file_rule failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	ret = reply->integer;
	freeReplyObject(reply);
	return ret;
}

SR_32 redis_mng_has_can_rule(redisContext *c, SR_32 rule_id)
{
    redisReply *reply;
    SR_32 ret;

	reply = redisCommand(c,"EXISTS %s%d", CAN_PREFIX, rule_id);
	if (reply == NULL || reply->type != REDIS_REPLY_INTEGER) {
		printf("ERROR: redis_mng_has_file_rule failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	ret = reply->integer;
	freeReplyObject(reply);
	return ret;
}

SR_32 redis_mng_has_action(redisContext *c, char *name)
{
    redisReply *reply;
    SR_32 ret;

	reply = redisCommand(c,"EXISTS %s%s", ACTION_PREFIX, name);
	if (reply == NULL || reply->type != REDIS_REPLY_INTEGER) {
		printf("ERROR: redis_mng_has_file_rule failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	ret = reply->integer;
	freeReplyObject(reply);
	return ret;
}

SR_32 redis_mng_has_list(redisContext *c, list_type_e type, char *name)
{
    redisReply *reply;
    SR_32 ret;

	reply = redisCommand(c,"EXISTS %d%s%s", type, LIST_PREFIX, name);
	if (reply == NULL || reply->type != REDIS_REPLY_INTEGER) {
		printf("ERROR: redis_mng_has_file_rule failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	ret = reply->integer;
	freeReplyObject(reply);
	return ret;
}
#if 0
SR_32 redis_mng_create_canbus_rule(redisContext *c, SR_32 rule_id, SR_U32 msg_id, char *interface, char *exec, char *user, char *action, SR_U8 dir)
{
	char msgid_str[9];
	char dir_str[4];
	
	sprintf(msgid_str, "%08x", msg_id);
	strcpy(dir_str, get_dir_desc(dir));
	// todo dir and int instead of in_int and out_int - fix
	redisAppendCommand(c,"HMSET %s%d %s %s %s %s %s %s %s %s %s %s %s %s", CAN_PREFIX, rule_id, ACTION, action,
			MID, msgid_str, IN_INTERFACE, dir_str, OUT_INTERFACE, interface, PROGRAM_ID, exec, USER_ID, user);
	redis_changes++;
	return SR_SUCCESS;
}
#endif

#if 0
SR_32 redis_mng_commit(redisContext *c)
{
	int rc, i, j;
	redisReply **replies;

	replies = malloc(sizeof(redisReply*) * redis_changes);
	if (replies == NULL)
		return SR_ERROR; // todo CEF

	// verify all operations succeeded
	for (i = 0; i < redis_changes; i++) {
		rc = redisGetReply(c, (void*)&replies[i]);
		if (rc) { // != REDIS_OK
			for (j = 0; j <= i; j++)
				freeReplyObject(replies[j]);
			free(replies);
			return SR_ERROR; // todo CEF
		}
	}

	for (i = 0; i < redis_changes; i++)
		freeReplyObject(replies[i]);
	free(replies);

	redis_changes = 0; // reset for next time
	return SR_SUCCESS;
}
#endif

SR_32 redis_mng_update_engine_state(redisContext *c, SR_BOOL is_on)
{
	// todo is this in the DB ?
	redisAppendCommand(c,"SET %s %s", ENGINE, is_on ? "start" : "stop");
	redis_changes++;
	return SR_SUCCESS;
}

#if 0
SR_32 redis_mng_create_action(redisContext *c, char *action_name, SR_BOOL is_allow, SR_BOOL is_log)
{
	redisAppendCommand(c,"HMSET %s%s %s %s %s %s %s %s %s %s", ACTION_PREFIX, action_name,
			BITMAP, is_allow ? "allow" : "drop", LOG, is_log ? "syslog" : "none", SMS, NULL, EMAIL, NULL);
	redis_changes++;
	return SR_SUCCESS;
}
#endif

SR_32 redis_mng_add_system_policer(redisContext *c, char *exec, redis_system_policer_t *sp)
{
	redisReply *reply;
	
	reply = redisCommand(c,"HMSET %s%s %s %lu %s %lu %s %u %s %u %s %u %s %u", SYSTEM_POLICER_PREFIX, exec,
		SP_UTIME, sp->utime,
		SP_STIME, sp->stime,
		SP_BYTES_READ, sp->bytes_read,
		SP_BYTES_WRITE, sp->bytes_write,
		SP_VM_ALLOC, sp->vm_allocated,
		SP_THREADS_NO, sp->num_of_threads);
	if (reply == NULL || reply->type != REDIS_REPLY_STATUS) {
		printf("ERROR: redis_mng_add_system_policer failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	freeReplyObject(reply);

	return SR_SUCCESS;
}

#define CHECK_PRINT(n) (replies[i]->elements > n) ?  replies[i]->element[n]->str : ""

static SR_32 print_cb(char *exec, redis_system_policer_t *sp)
{
	printf("exec:%s utime:%llu stime:%llu byte read:%u byte write:%u vm alloc:%u num of threads:%u \n",
				exec, sp->utime, sp->stime, sp->bytes_read, sp->bytes_write, sp->vm_allocated, sp->num_of_threads);
	return SR_SUCCESS;
}

SR_32 redis_mng_print_system_policer(redisContext *c)
{
	return redis_mng_exec_all_system_policer(c, print_cb);
}

SR_32 redis_mng_exec_all_system_policer(redisContext *c, SR_32 (*cb)(char *exec, redis_system_policer_t *sp))
{
	int i, j;
	redisReply *reply;
	redisReply **replies;
	redis_system_policer_t sp = {};
	// get all keys
	reply = redisCommand(c,"KEYS %s*", SYSTEM_POLICER_PREFIX);
	if (reply == NULL || reply->type != REDIS_REPLY_ARRAY) {
		printf("ERROR: redis_mng_print_system_policer failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}

	replies = malloc(sizeof(redisReply*) * reply->elements);
	if (!replies) {
		printf("ERROR: redis_mng_print_system_policer allocation failed\n");
		freeReplyObject(reply);
		return SR_ERROR;
	}

	for (i = 0; i < reply->elements; i++)
		redisAppendCommand(c,"HGETALL %s", reply->element[i]->str);

	for (i = 0; i < (int)reply->elements; i++) {
		if (redisGetReply(c, (void*)&replies[i]) != REDIS_OK) {
			printf("ERROR: redisGetReply %d failed\n", i);
			for (j = 0; j < i; j++)
				freeReplyObject(replies[j]);
			free(replies);
			freeReplyObject(reply);
			return SR_ERROR;
		}
		if (replies[i]->type != REDIS_REPLY_ARRAY) {
			printf("ERROR: redisGetReply %d type is wrong %d\n", i, replies[i]->type);
			for (j = 0; j < i; j++)
				freeReplyObject(replies[j]);
			free(replies);
			freeReplyObject(reply);
			return SR_ERROR;
		}

		memset(&sp, 0, sizeof(sp));
		if (replies[i]->elements > 1) 
			sp.utime = atol(replies[i]->element[1]->str);
		if (replies[i]->elements > 3) 
			sp.bytes_read = atol(replies[i]->element[3]->str);
		if (replies[i]->elements > 5) 
			sp.bytes_write = atol(replies[i]->element[5]->str);
		if (replies[i]->elements > 7) 
			sp.vm_allocated = atol(replies[i]->element[7]->str);
		if (replies[i]->elements > 9) 
			sp.num_of_threads = atol(replies[i]->element[9]->str);
		if (cb)
			cb(reply->element[i]->str + strlen(SYSTEM_POLICER_PREFIX), &sp);
	}

	// free replies
	for (i = 0; i < reply->elements; i++)
		freeReplyObject(replies[i]);
	free(replies);
	freeReplyObject(reply);
	return SR_SUCCESS;
}
