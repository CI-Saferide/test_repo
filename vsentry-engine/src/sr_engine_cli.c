#include "sr_types.h"
#include "sr_engine_main.h"
#include "sr_engine_cli.h"
#include "sr_db.h"
#include "sr_db_file.h"
#include "sr_db_ip.h"
#include "sr_db_can.h"
#include "sal_linux.h"
#include "sysrepo_mng.h"
#include "db_tools.h"

static void engine_status_dump(int fd)
{
	char buf[100];
	SR_32 len, n;

	sprintf(buf, "engine,%s%c", get_engine_state() ? "on" : "off", SR_CLI_END_OF_ENTITY);
	len = strlen(buf);
	if ((n = write(fd, buf, len)) < len) {
                printf("Write to CLI file failed \n");
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=write to cli for file failed.",REASON);
        }       
}

void sr_engine_cli_load(SR_32 fd)
{
	char buf[2] = {};

	engine_status_dump(fd);
	action_dump(fd);
	file_rule_dump_rules(fd);
	ip_rule_dump_rules(fd);
	can_rule_dump_rules(fd);
	buf[0] = SR_CLI_END_OF_TRANSACTION;
	if (write(fd, buf, 1) < 1) {
		printf("write failed buf\n");
	}
}

static SR_32 handle_engine_commit(sysrepo_mng_handler_t *handler, char *buf)
{
	char *ptr, *help_str = NULL;
	SR_32 rc = SR_SUCCESS;

	help_str = strdup(buf);
	ptr = strtok(help_str, ",");
	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=engine buf correpted ",REASON);
		rc = SR_ERROR;
		goto out;
	}

	if (sys_repo_mng_update_engine_state(handler, strcmp(ptr, "on") == 0 ? SR_TRUE : SR_FALSE) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=engine buf correpted ",REASON);
		rc = SR_ERROR;
		goto out;
	}

out:
	if (help_str)
		free(help_str);
	return rc;
}

static SR_32 handle_action_commit(sysrepo_mng_handler_t *handler, char *buf)
{
	char *ptr, *help_str = NULL, action_name[ACTION_STR_SIZE];
	action_e action;
	log_facility_e log_facility;
	SR_32 st = SR_SUCCESS;

	help_str = strdup(buf);
	ptr = strtok(help_str, ",");
		
	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=asction buf correpted ",REASON);
		st = SR_ERROR;
		goto out;
	}
	strncpy(action_name, ptr, ACTION_STR_SIZE);

	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=asction buf correpted ",REASON);
		st = SR_ERROR;
		goto out;
	}
	action = get_action_code(ptr);

	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=asction buf correpted ",REASON);
		st = SR_ERROR;
		goto out;
	}
	log_facility = get_action_log_facility_code(ptr);

	if (sys_repo_mng_create_action(handler, action_name, action == ACTION_ALLOW, log_facility != LOG_NONE) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=asction buf correpted ",REASON);
		st = SR_ERROR;
		goto out;
	}

out:
	if (help_str)
		free(help_str);

	return st;
}

static SR_32 handle_file_commit(sysrepo_mng_handler_t *handler, SR_U32 rule_id, SR_U32 tuple_id)
{
	char action_name[ACTION_STR_SIZE], file_name[FILE_NAME_SIZE], user[USER_NAME_SIZE], program[PROG_NAME_SIZE], perms[4], *ptr;

	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=file rule buf correpted ",REASON);
		return SR_ERROR;
	}
        strncpy(action_name, ptr, ACTION_STR_SIZE);

	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=file rule buf correpted ",REASON);
		return SR_ERROR;
	}
        strncpy(file_name, ptr, FILE_NAME_SIZE);

	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=file rule buf correpted ",REASON);
		return SR_ERROR;
	}
	strncpy(perms, ptr, 4);

	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=file rule buf correpted ",REASON);
		return SR_ERROR;
	}
        strncpy(user, ptr, USER_NAME_SIZE);

	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=file rule buf correpted ",REASON);
		return SR_ERROR;
	}
        strncpy(program, ptr, PROG_NAME_SIZE);

	if (sys_repo_mng_create_file_rule(handler, rule_id, tuple_id, file_name, program, user, action_name,
		sys_repo_mng_perm_get_code(perms)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=create file rule failed ",REASON);
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

static SR_32 handle_ip_commit(sysrepo_mng_handler_t *handler, SR_U32 rule_id, SR_U32 tuple_id)
{
	char *ptr, action_name[ACTION_STR_SIZE], src_addr[IPV4_STR_MAX_LEN], src_netmask[IPV4_STR_MAX_LEN];
	char dst_addr[IPV4_STR_MAX_LEN], dst_netmask[IPV4_STR_MAX_LEN], user[USER_NAME_SIZE], program[PROG_NAME_SIZE];
	SR_U16 src_port, dst_port;
	SR_U8 ip_proto;

	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=file rule buf correpted ",REASON);
		return SR_ERROR;
	}
        strncpy(action_name, ptr, ACTION_STR_SIZE);

	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=file rule buf correpted ",REASON);
		return SR_ERROR;
	}
	strncpy(src_addr, ptr, IPV4_STR_MAX_LEN);
	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=file rule buf correpted ",REASON);
		return SR_ERROR;
	}
	strncpy(src_netmask, ptr, IPV4_STR_MAX_LEN);
	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=file rule buf correpted ",REASON);
		return SR_ERROR;
	}
	strncpy(dst_addr, ptr, IPV4_STR_MAX_LEN);
	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=file rule buf correpted ",REASON);
		return SR_ERROR;
	}
	strncpy(dst_netmask, ptr, IPV4_STR_MAX_LEN);
	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=file rule buf correpted ",REASON);
		return SR_ERROR;
	}
	ip_proto = atoi(ptr);
	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=file rule buf correpted ",REASON);
		return SR_ERROR;
	}
	src_port = atoi(ptr);
	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=file rule buf correpted ",REASON);
		return SR_ERROR;
	}
	dst_port = atoi(ptr);
	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=file rule buf correpted ",REASON);
		return SR_ERROR;
	}
        strncpy(user, ptr, USER_NAME_SIZE);
	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=file rule buf correpted ",REASON);
		return SR_ERROR;
	}
        strncpy(program, ptr, PROG_NAME_SIZE);

#ifdef CLI_DEBUG
	printf("IP %d,%d action:%s src_addr:%s: src_netmask:%s: src_addr:%s: src_netmask:%s: ip_proto:%d src_port:%d dst_port :%d user:%s program:%s \n",
		rule_id, tuple_id, action_name, src_addr, src_netmask,
		dst_addr, dst_netmask, ip_proto, src_port, dst_port, user, program);
#endif

	if (sys_repo_mng_create_net_rule(handler, rule_id, tuple_id, src_addr, src_netmask, dst_addr, dst_netmask, ip_proto, 
        	src_port, dst_port, program, user, action_name) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=create file rule failed ",REASON);
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

static SR_32 handle_can_commit(sysrepo_mng_handler_t *handler, SR_U32 rule_id, SR_U32 tuple_id)
{
	char *ptr, action_name[ACTION_STR_SIZE], user[USER_NAME_SIZE], program[PROG_NAME_SIZE], interface[INTERFACE_SIZE];
	SR_16 msg_id;
	SR_U8 dir;

	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=file rule buf correpted 1",REASON);
		return SR_ERROR;
	}
        strncpy(action_name, ptr, ACTION_STR_SIZE);
	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=file rule buf correpted 2",REASON);
		return SR_ERROR;
	}
	msg_id = atoi(ptr);
	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=file rule buf correpted 4",REASON);
		return SR_ERROR;
	}
	dir = atoi(ptr);
	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=file rule buf correpted 5",REASON);
		return SR_ERROR;
	}
        strncpy(interface, ptr, INTERFACE_SIZE);
	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=file rule buf correpted 6",REASON);
		return SR_ERROR;
	}
        strncpy(user, ptr, USER_NAME_SIZE);
	if (!(ptr = strtok(NULL, ","))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=file rule buf correpted 7",REASON);
		return SR_ERROR;
	}
        strncpy(program, ptr, PROG_NAME_SIZE);

#ifdef CLI_DEBUG
	printf("CAN COMMIT rule:%d t:%d action:%s: msg:%x dir:%d interface:%s user:%s program:%s \n", rule_id, tuple_id, action_name, msg_id, dir, interface, user, program);
#endif

	if (sys_repo_mng_create_canbus_rule(handler, rule_id, tuple_id, msg_id, interface, program, user, action_name, dir) != SR_SUCCESS) {
		printf("Commit Failed Create can rule \n");
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=fail to create can rule in persistent db. rule id:%d tuple:%d mid:%x",
			REASON, rule_id, tuple_id, msg_id);
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

static SR_32 handle_buffer(sysrepo_mng_handler_t *handler, char *buf)
{
	char *ptr, *help_str = NULL;
	SR_U32 rule_id, tuple_id;

	if (!memcmp(buf, "action", strlen("action")))
                return handle_action_commit(handler, buf);
	if (!memcmp(buf, "engine", strlen("engine")))
                return handle_engine_commit(handler, buf);

	help_str = strdup(buf);
        ptr = strtok(help_str, ",");
        ptr = strtok(NULL, ",");
        rule_id = atoi(ptr);
        ptr = strtok(NULL, ",");
        tuple_id = atoi(ptr);

	if (!memcmp(buf, "file", strlen("file"))) {
                handle_file_commit(handler, rule_id, tuple_id);
        }
	if (!memcmp(buf, "ip", strlen("ip"))) {
                handle_ip_commit(handler, rule_id, tuple_id);
        }
	if (!memcmp(buf, "can", strlen("can"))) {
                handle_can_commit(handler, rule_id, tuple_id);
        }

	if (help_str)
		free(help_str);
	return SR_SUCCESS;
}

SR_32 sr_engine_cli_commit(SR_32 fd)
{
        SR_U32 len, ind;
	SR_32 st = SR_SUCCESS;
        char cval, buf[10000], syncbuf[2] = {};
	sysrepo_mng_handler_t sysrepo_handler;

        // Snc 
	syncbuf[0] = SR_CLI_END_OF_TRANSACTION;
	if (write(fd, syncbuf, 1) < 1) {
		printf("Failed writing sync buf\n");
		return SR_ERROR;
	}

        if (sysrepo_mng_session_start(&sysrepo_handler) != SR_SUCCESS) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=sysrepo_mng_session_start failed",REASON);
                return SR_ERROR;
        }

	/* Delete all DB */
	if (sysrepo_mng_delete_all(&sysrepo_handler, SR_FALSE)) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
		"%s=cli commit failed delete DB failed", REASON);
		return SR_ERROR;
	}

        buf[0] = 0;
        ind = 0;
        for (;;) {
                len = read(fd, &cval, 1);
                if (!len) {
                        printf("Failed reading from socket");
                        st = SR_ERROR;
			goto out;
                }
                switch (cval) {
                        case SR_CLI_END_OF_TRANSACTION: /* Finish commit */
        			if (sys_repo_mng_commit(&sysrepo_handler) != SR_SUCCESS) {
                			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                			"%s=sysrepo commit failed ", REASON);
					st = SR_ERROR;
        			}
                                goto out;
                        case SR_CLI_END_OF_ENTITY: /* Finish entity */
                                buf[ind] = 0;
#ifdef CLI_DEBUG
                                printf("----- Got buffer:%s:----------------------- \n", buf);
#endif
				if (handle_buffer(&sysrepo_handler, buf) != SR_SUCCESS) {
					printf("Error handle buffer failed buf:%s: \n", buf);
                			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                				"%s=handle buffer failed buf:%s:", REASON, buf);
					st = SR_ERROR;
					goto out;
				}
                                buf[0] = 0;
                                ind = 0;
                                break;
                        default:
                                buf[ind++] = cval;
                                break;
                }
        }

out:
        if (sysrepo_mng_session_end(&sysrepo_handler) != SR_SUCCESS) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                "%s=sysrepod session end failed ", REASON);
		st = SR_ERROR;
	}

	// Snc 
	syncbuf[0] = SR_CLI_END_OF_TRANSACTION;
	if (write(fd, syncbuf, 1) < 1) {
		printf("Failed writing sync buf\n");
		return SR_ERROR;
	}

        return st;
}


