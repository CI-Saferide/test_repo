/* sr_config.c */
#include "sr_config.h"
#include "sr_sal_common.h"
#include "sr_cls_network_common.h"
#include "sr_cls_port_control.h"
#include "sr_cls_network_control.h"
#include "sr_cls_rules_control.h"
#include "sr_cls_canbus_control.h"
#include "sr_cls_file_control.h"
#include "confd_lib.h"
#include "sr_msg.h"
#include "confd_cdb.h"
#include "saferide.h"
#include "sr_msg_dispatch.h"
#include "sr_control.h"
#include "sr_confd.h"
//need to move these headers to sal_linux.h
#include <arpa/inet.h>
#include <pthread.h>
#include <poll.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sr_file_hash.h>

static int send_cleanup_messgae(void)
{
	sr_msg_dispatch_hdr_t *msg;

        msg = (sr_msg_dispatch_hdr_t *)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
	if (msg) {
		msg->msg_type = SR_MSG_TYPE_CLS_CLEANUP_NOLOCK;
		sr_send_msg(ENG2MOD_BUF, sizeof(msg));
	}

        return SR_SUCCESS;
}

static void *handle_commit_trd(void *p)
{
	struct sockaddr_in addr;
	int subsock;
	int status;
	int spoint;

	addr.sin_addr.s_addr = inet_addr(CONFD_SERVER);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(CONFD_PORT);

	confd_init("SafeRide", stderr, CONFD_TRACE);

	if ((subsock = socket(PF_INET, SOCK_STREAM, 0)) < 0 )
		confd_fatal("Failed to open socket\n");

	if (cdb_connect(subsock, CDB_SUBSCRIPTION_SOCKET, (struct sockaddr*)&addr,
					sizeof (struct sockaddr_in)) < 0)
		confd_fatal("Failed to confd_connect() to confd \n");

	if ((status = cdb_subscribe(subsock, 3, saferide__ns, &spoint,"/"))
		!= CONFD_OK) {
		fprintf(stderr, "Terminate: subscribe %d\n", status);
		exit(0);
	}

	if (cdb_subscribe_done(subsock) != CONFD_OK)
		confd_fatal("cdb_subscribe_done() failed");

	fprintf(stderr, "Subscription point = %d\n", spoint);

	while (1) {
		struct pollfd set[1];

		set[0].fd = subsock;
		set[0].events = POLLIN;
		set[0].revents = 0;

		if (poll(set, sizeof(set)/sizeof(*set), -1) < 0) {
			perror("Poll failed:");
			continue;
		}

		/* Check for I/O */
		if (set[0].revents & POLLIN) {
			int sub_points[1];
			int reslen;
			if ((status = cdb_read_subscription_socket(subsock,
						   &sub_points[0], &reslen)) != CONFD_OK)
				exit(status);

			if (reslen > 0) {
	    			sal_printf("Got COMMIT notification \n");
				sr_control_set_state(SR_FALSE);
				send_cleanup_messgae();
				sr_control_set_state(SR_TRUE);
        			read_config_db();
			}
			/* This is the place where we may act on the newly read configuration */

			if ((status = cdb_sync_subscription_socket(subsock, CDB_DONE_PRIORITY))
				!= CONFD_OK) {
				exit(status);
			}
		}
	}

	cdb_close(subsock);

	return NULL;
}

SR_BOOL handle_commit_events(void)
{
	pthread_t t;

        pthread_create(&t, NULL, handle_commit_trd, NULL);

	return SR_TRUE;
}

SR_BOOL write_config_record (void* ptr, enum sr_header_type rec_type)
{
	FILE* 					conf_file;
	conf_file = fopen(filename,"ab");
	switch (rec_type) {
	case CONFIG_NET_RULE: {
		struct sr_net_record	net_rec;
		struct sr_net_entry*	net_entry;
		memcpy(&net_rec, ptr, sizeof(net_rec));
		net_entry = (struct sr_net_entry*)ptr;
		fwrite(&rec_type, 1, sizeof(rec_type),conf_file);
		fwrite(&net_rec, 1, sizeof(net_rec),conf_file);
		fwrite(net_entry->process, net_entry->process_size, sizeof(SR_8),conf_file);
		break;
		}
	case CONFIG_FILE_RULE: {
		struct sr_file_record	file_rec;
		struct sr_file_entry*	file_entry;
		memcpy(&file_rec, ptr, sizeof(file_rec));
		file_entry = (struct sr_file_entry*)ptr;
		fwrite(&rec_type, 1, sizeof(rec_type),conf_file);
		fwrite(&file_rec, 1, sizeof(file_rec),conf_file);
		fwrite(file_entry->process, file_entry->process_size, sizeof(SR_8),conf_file);
		fwrite(file_entry->filename, file_entry->filename_size, sizeof(SR_8),conf_file);
		break;
		}
	case CONFIG_CAN_RULE: {
		struct sr_can_record		can_rec;
		struct sr_can_entry*		can_entry;
		memcpy(&can_rec, ptr, sizeof(can_rec));
		can_entry = (struct sr_can_entry*)ptr;
		fwrite(&rec_type, 1, sizeof(rec_type),conf_file);
		fwrite(&can_rec, 1, sizeof(can_rec),conf_file);
		fwrite(can_entry->process, can_entry->process_size, sizeof(SR_8),conf_file);
		break;
		}
	case CONFIG_PHONE_ENTRY: {
		struct sr_phone_record*	phone_entry;
		phone_entry = (struct sr_phone_record*)ptr;
		fwrite(&rec_type, 1, sizeof(rec_type),conf_file);
		fwrite(phone_entry, 1, sizeof(struct sr_phone_record),conf_file);
		break;
		}
	case CONFIG_EMAIL_ENTRY: {
		struct sr_email_record		email_rec;
		struct sr_email_entry*		email_entry;
		memcpy(&email_rec, ptr, sizeof(email_rec));
		email_entry = (struct sr_email_entry*)ptr;
		fwrite(&rec_type, 1, sizeof(rec_type),conf_file);
		fwrite(&email_rec, 1, sizeof(email_rec),conf_file);
		fwrite(email_entry->email, email_entry->email_size, sizeof(SR_8),conf_file);
		break;
		}
	case CONFIG_LOG_TARGET: {
		struct sr_log_record		log_rec;
		struct sr_log_entry*		log_entry;
		memcpy(&log_rec, ptr, sizeof(log_rec));
		log_entry = (struct sr_log_entry*)ptr;
		fwrite(&rec_type, 1, sizeof(rec_type),conf_file);
		fwrite(&log_rec, 1, sizeof(log_rec),conf_file);
		fwrite(log_entry->log_target, log_entry->log_size, sizeof(SR_8),conf_file);
		break;
		}
	default:
		fclose (conf_file);
		return SR_FALSE;
		break;
	};
	
	fclose (conf_file);
	return SR_TRUE;
}

static void extract_action(int rsock, sr_action_cfg* action, char *action_name)
{
       char list_action_name[ACTION_NAME_SIZE];
        char tmp[128];
        int i, j, n, st;

        memset(action, 0, sizeof(sr_action_cfg));

        n = cdb_num_instances(rsock, CONFD_CONFIG_PATH_PREFIX "/sr_actions/list_actions");

        for (i=0; i<n; i++) {
                memset(list_action_name, 0, ACTION_NAME_SIZE);
                cdb_get_str(rsock, list_action_name, ACTION_NAME_SIZE, CONFD_CONFIG_PATH_PREFIX "/sr_actions/list_actions[%d]/name", i);

                if(strncmp(action_name, list_action_name, strlen(action_name)) == 0) {
                        strncpy(action->action_name, action_name, ACTION_NAME_SIZE);

                        memset(tmp, 0, 128);
                        cdb_get_str(rsock, tmp, ACTION_NAME_SIZE, CONFD_CONFIG_PATH_PREFIX "/sr_actions/list_actions[%d]/action", i);
			action->action = SR_ACTION_ALLOW; /* Default */
			if (!strncmp(tmp, ACTION_DROP, ACTION_NAME_SIZE))
			    action->action = SR_ACTION_DROP;

			memset(tmp, 0, 128);
			st = cdb_get_str(rsock, tmp, ACTION_NAME_SIZE, CONFD_CONFIG_PATH_PREFIX "/sr_actions/list_actions[%d]/log/log_facility", i);
			if (!st) {
				for (j=0; j<SR_LOG_TOTAL; j++) {
					if (strncmp(tmp, sr_log_facility_str[j], strlen(tmp)) == 0) {
						action->log_facility = j;
						action->is_log = SR_TRUE;
						break;
					}
				}
			}

                        memset(tmp, 0, 128);
                        cdb_get_str(rsock, tmp, ACTION_NAME_SIZE, CONFD_CONFIG_PATH_PREFIX "/sr_actions/list_actions[%d]/log/log_severity", i);
                        for (j=0; j<SR_LOG_SEVERITY_TOTAL; j++) {
                                if (strncmp(tmp, sr_log_severity_str[j], strlen(tmp)) == 0) {
                                        action->log_severity = j;
                                        break;
                                }
                        }

                        cdb_get_bool(rsock, &action->black_list, CONFD_CONFIG_PATH_PREFIX "/sr_actions/list_actions[%d]/black-list", i);
                        cdb_get_bool(rsock, &action->terminate, CONFD_CONFIG_PATH_PREFIX "/sr_actions/list_actions[%d]/terminate", i);
                }
        }
}

static void convert_action(sr_action_cfg *action, SR_U16 *bitmap)
{
	switch (action->action) {
		case SR_ACTION_DROP:
			*bitmap = SR_CLS_ACTION_DROP;
			break;
		case SR_ACTION_ALLOW:
			*bitmap = SR_CLS_ACTION_ALLOW;
			break;
		case SR_ACTION_TOTAL:
		default:
			printf("No action\n");
			break;
	}
	if (action->is_log)
		*bitmap |= SR_CLS_ACTION_LOG;
} 

static void handle_engine_start_stop(int rsock)
{
	FILE *f;
	char engine[ENGINE_NAME_SIZE] = "";

	cdb_cd(rsock, CONFD_CONTROL_PATH_PREFIX "/");
	cdb_get_str(rsock, engine , ACTION_NAME_SIZE, "engine");
	if (!strncmp(engine, ENGINE_START, ENGINE_NAME_SIZE)) {
		sr_control_set_state(SR_TRUE);
		f = fopen("/tmp/sec_state", "w");
		fprintf(f, "on");
		fclose(f);
	} else if (!strncmp(engine, ENGINE_STOP, ENGINE_NAME_SIZE)) {
		sr_control_set_state(SR_FALSE);
		f = fopen("/tmp/sec_state", "w");
		fprintf(f, "off");
		fclose(f);
	}
}

static void extract_can_rules(int rsock, int num_of_rules)
{
        int i, j, num_of_tuples;
        can_rule can_rule = {};
        char action_name[ACTION_NAME_SIZE] = "";
	SR_U16 actions_bitmap = 0;

        for (i = 0; i < num_of_rules; i++) {
            cdb_cd(rsock, CONFD_CONFIG_PATH_PREFIX "/net/can/rule[%d]", i);
	    /* get rule number */
	    cdb_get_u_int16(rsock, &can_rule.rulenum, "num");
	    cdb_get_str(rsock, action_name , ACTION_NAME_SIZE, "action");
            if (strlen(action_name) > 0) {
                extract_action(rsock, &can_rule.action, action_name);
		convert_action(&can_rule.action, &actions_bitmap);
            }
	    num_of_tuples = cdb_num_instances(rsock, "tuple");
	    for (j = 0; j < num_of_tuples; j++) {
		 cdb_get_u_int32(rsock, &can_rule.tuple.msg_id, "tuple[%d]/msg_id", j);
		 cdb_get_str(rsock, can_rule.tuple.user, USER_NAME_SIZE, "tuple[%d]/user", j);
		 cdb_get_str(rsock, can_rule.tuple.program, PROG_NAME_SIZE, "tuple[%d]/program", j);
		 cdb_get_u_int32(rsock, &can_rule.tuple.max_rate, "tuple[%d]/max_rate", j);
		 sr_cls_canid_add_rule(can_rule.tuple.msg_id, *can_rule.tuple.program ? can_rule.tuple.program : "*", 
			*can_rule.tuple.user ? can_rule.tuple.user : "*", can_rule.rulenum);
                 sr_cls_rule_add(SR_CAN_RULES, can_rule.rulenum, actions_bitmap, 0, can_rule.tuple.max_rate, /* can_rule.rate_action */ 0,  /* can_rule.action.log_target */ 0,
			/* email_id*/ 0, /* can_rule.action.phone_id*/ 0, /*can_rule.action.skip_rulenum */ 0);
	    }
	}
}

static void convert_permissions(char *permissions, SR_U8 *premisions_bitmaps)
{
	if (!permissions)
		return;

	*premisions_bitmaps = 0;
	if (strchr(permissions, 'x'))
		*premisions_bitmaps |= SR_FILEOPS_EXEC;
	if (strchr(permissions, 'w'))
		*premisions_bitmaps |= SR_FILEOPS_WRITE;
	if (strchr(permissions, 'r'))
		*premisions_bitmaps |= SR_FILEOPS_READ;
}

static void extract_system_rules(int rsock, int num_of_rules)
{
        int i, j, num_of_tuples;
		SR_U32 rc;
        file_rule file_rule = {};
        char action_name[ACTION_NAME_SIZE] = "";
		SR_U16 actions_bitmap = 0;
		SR_U8 permissions = 0;

		/* Clean the file hash */ 
		if ((rc = sr_file_hash_delete_all()) != SR_SUCCESS) {
			sal_printf("extract_system_rules sr_file_hash_delete_all failed\n");
		}

        for (i = 0; i < num_of_rules; i++) {
            cdb_cd(rsock, CONFD_CONFIG_PATH_PREFIX "/system/file/rule[%d]", i);
	    /* get rule number */
	    cdb_get_u_int16(rsock, &file_rule.rulenum, "num");
	    cdb_get_str(rsock, action_name , ACTION_NAME_SIZE, "action");
            if (strlen(action_name) > 0) {
                extract_action(rsock, &file_rule.action, action_name);
		convert_action(&file_rule.action, &actions_bitmap);
            }
	    num_of_tuples = cdb_num_instances(rsock, "tuple");
	    for (j = 0; j < num_of_tuples; j++) {
		 cdb_get_str(rsock, file_rule.tuple.name, FILE_NAME_SIZE, "tuple[%d]/filename", j);
		 cdb_get_str(rsock, file_rule.tuple.program, PROG_NAME_SIZE, "tuple[%d]/program", j);
		 cdb_get_str(rsock, file_rule.tuple.user, USER_NAME_SIZE, "tuple[%d]/user", j);
		 cdb_get_str(rsock, file_rule.tuple.permission, FILE_PERM_SIZE, "tuple[%d]/permission", j);
		 convert_permissions(*file_rule.tuple.permission ? file_rule.tuple.permission : "xwr" , &permissions);
		 sr_cls_file_add_rule(file_rule.tuple.name, *file_rule.tuple.program ? file_rule.tuple.program : "*", 
			*file_rule.tuple.user ? file_rule.tuple.user : "*", file_rule.rulenum, 1);
                 sr_cls_rule_add(SR_FILE_RULES, file_rule.rulenum, actions_bitmap, permissions, /* file_rule_tuple.max_rate */ 0, /* file_rule.rate_action */ 0 ,
			 /* file_ruole.action.log_target */ 0 , /* file_rule.tuple.action.email_id */ 0 , /* file_rule.tuple.action.phone_id */ 0 , /* file_rule.action.skip_rulenum */ 0);
		  if ((rc = sr_file_hash_update_rule(file_rule.tuple.name, *file_rule.tuple.program ? file_rule.tuple.program : "*",
			*file_rule.tuple.user ? file_rule.tuple.user : "*", file_rule.rulenum, actions_bitmap, permissions)) != SR_SUCCESS) {
			sal_printf("extract_system_rules sr_file_hash_update_rule failed\n");
		  }
	    }
	}
}

static void handle_local_address(struct in_addr *addr)
{
	char ip[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, addr, ip, INET_ADDRSTRLEN); 
	if (!strcmp(ip, "127.0.0.1"))
		addr->s_addr = 0;
}

static void extract_net_rules(int rsock, int num_of_rules)
{
        int i, j, num_of_tuples;
        network_rule net_rule = {};
        char action_name[ACTION_NAME_SIZE] = "";
	SR_U16 actions_bitmap = 0;

        for (i = 0; i < num_of_rules; i++) {
            cdb_cd(rsock, CONFD_CONFIG_PATH_PREFIX "/net/ip/rule[%d]", i);
	    /* get rule number */
	    cdb_get_u_int16(rsock, &net_rule.rulenum, "num");
	    cdb_get_str(rsock, action_name , ACTION_NAME_SIZE, "action");
            if (strlen(action_name) > 0) {
                extract_action(rsock, &net_rule.action, action_name);
		convert_action(&net_rule.action, &actions_bitmap);
            }
	    num_of_tuples = cdb_num_instances(rsock, "tuple");
	    for (j = 0; j < num_of_tuples; j++) {
		cdb_get_ipv4(rsock, &net_rule.tuple.srcaddr, "tuple[%d]/srcaddr", j);
		handle_local_address(&net_rule.tuple.srcaddr);
		cdb_get_ipv4(rsock, &net_rule.tuple.srcnetmask, "tuple[%d]/srcnetmask", j);
		if (!net_rule.tuple.srcaddr.s_addr)
			net_rule.tuple.srcnetmask.s_addr = 0;
		cdb_get_ipv4(rsock, &net_rule.tuple.dstaddr, "tuple[%d]/dstaddr", j);
		handle_local_address(&net_rule.tuple.dstaddr);
		cdb_get_ipv4(rsock, &net_rule.tuple.dstnetmask, "tuple[%d]/dstnetmask", j);
		if (!net_rule.tuple.dstaddr.s_addr)
			net_rule.tuple.dstnetmask.s_addr = 0;
		cdb_get_u_int16(rsock, &net_rule.tuple.dstport, "tuple[%d]/dstport", j);
		cdb_get_u_int16(rsock, &net_rule.tuple.srcport, "tuple[%d]/srcport", j);
		cdb_get_u_int8(rsock, &net_rule.tuple.proto, "tuple[%d]/proto", j);
		cdb_get_str(rsock, net_rule.tuple.user, USER_NAME_SIZE, "tuple[%d]/user", j);
		cdb_get_str(rsock, net_rule.tuple.program, PROG_NAME_SIZE, "tuple[%d]/program", j);
		sr_cls_port_add_rule(net_rule.tuple.srcport, *net_rule.tuple.program ? net_rule.tuple.program : "*", 
			*net_rule.tuple.user ? net_rule.tuple.user : "*", net_rule.rulenum, SR_DIR_SRC, net_rule.tuple.proto);
		sr_cls_port_add_rule(net_rule.tuple.dstport, *net_rule.tuple.program ? net_rule.tuple.program : "*", 
			*net_rule.tuple.user ? net_rule.tuple.user : "*", net_rule.rulenum, SR_DIR_DST, net_rule.tuple.proto);
	 	sr_cls_add_ipv4(net_rule.tuple.srcaddr.s_addr , *net_rule.tuple.program ? net_rule.tuple.program : "*", 
			*net_rule.tuple.user ? net_rule.tuple.user : "*", net_rule.tuple.srcnetmask.s_addr, net_rule.rulenum, SR_DIR_SRC);
	 	sr_cls_add_ipv4(net_rule.tuple.dstaddr.s_addr, *net_rule.tuple.program ? net_rule.tuple.program : "*", 
			*net_rule.tuple.user ? net_rule.tuple.user : "*", net_rule.tuple.dstnetmask.s_addr, net_rule.rulenum, SR_DIR_DST);
                sr_cls_rule_add(SR_NET_RULES, net_rule.rulenum, actions_bitmap, SR_FILEOPS_READ, /* net_rule_tuple.max_rate */ 0, /* net_rule.rate_action */ 0 ,
			 /* net_ruole.action.log_target */ 0 , /* net_rule.tuple.action.email_id */ 0 , /* net_rule.tuple.action.phone_id */ 0 , /* net_rule.action.skip_rulenum */ 0);
	    }
	}
}

SR_BOOL read_config_db (void)
{
	struct sockaddr_in addr;
	int rsock, n;

	addr.sin_addr.s_addr = inet_addr(CONFD_SERVER);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(CONFD_PORT);

	confd_init("SafeRide", stderr, CONFD_TRACE);

        if ((rsock = socket(PF_INET, SOCK_STREAM, 0)) < 0 ) {
	    sal_printf("fail to open confd socket \n");
	    return SR_FALSE;
	}

	if (cdb_connect(rsock, CDB_READ_SOCKET, (struct sockaddr*)&addr,
                sizeof (struct sockaddr_in)) < 0) {
	         sal_printf("fail to connect to confd socket \n");
                return SR_FALSE;
        }

        if (cdb_start_session(rsock, CDB_RUNNING) != CONFD_OK)
                return CONFD_ERR;

        cdb_set_namespace(rsock, saferide__ns);

	n = cdb_num_instances(rsock, CONFD_CONFIG_PATH_PREFIX "/net/can/rule");
	handle_engine_start_stop(rsock);
	if (n > 0)
        	extract_can_rules(rsock, n);
	n = cdb_num_instances(rsock, CONFD_CONFIG_PATH_PREFIX "/system/file/rule");
	if (n > 0)
        	extract_system_rules(rsock, n);
	n = cdb_num_instances(rsock, CONFD_CONFIG_PATH_PREFIX "/net/ip/rule");
	if (n > 0)
        	extract_net_rules(rsock, n);

	cdb_close(rsock);

	return SR_TRUE;
}

SR_BOOL read_config_file (void)
{
	FILE* 					conf_file;
	char					process[4096];
	enum sr_header_type		rec_type;
	conf_file = fopen(filename,"rb");
	
	if (!conf_file) {
		return SR_TRUE;
	}

	while (!feof(conf_file)) {
		if (1 != fread(&rec_type, sizeof(rec_type), 1, conf_file)) {
				fclose (conf_file);
				return SR_FALSE;
			}
		switch (rec_type) {
		case CONFIG_NET_RULE: {
			struct sr_net_record	net_rec;
			if (1 != fread(&net_rec, sizeof(net_rec), 1, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			memset(process, 0, 4096);
			if (net_rec.process_size != fread(&process, sizeof(SR_8), net_rec.process_size, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			sr_cls_port_add_rule(net_rec.src_port, process, "*", net_rec.rulenum, SR_DIR_SRC, net_rec.proto);
			sr_cls_port_add_rule(net_rec.dst_port, process, "*", net_rec.rulenum, SR_DIR_DST, net_rec.proto);
			sr_cls_add_ipv4(htonl(net_rec.src_addr), process, "*", htonl(net_rec.src_netmask), net_rec.rulenum, SR_DIR_SRC);
			sr_cls_add_ipv4(htonl(net_rec.dst_addr), process, "*", htonl(net_rec.dst_netmask), net_rec.rulenum, SR_DIR_DST);
			sr_cls_rule_add(SR_NET_RULES, net_rec.rulenum, net_rec.action.actions_bitmap, 0, net_rec.max_rate, net_rec.rate_action, net_rec.action.log_target, net_rec.action.email_id, net_rec.action.phone_id, net_rec.action.skip_rulenum);
			break;
			}
		case CONFIG_FILE_RULE: {
			struct sr_file_record	file_rec;
			char					filename[4096];
			if (1 != fread(&file_rec, sizeof(file_rec), 1, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			memset(process, 0, 4096);
			memset(filename, 0, 4096);
			if (file_rec.process_size != fread(&process, sizeof(SR_8), file_rec.process_size, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			if (file_rec.filename_size != fread(&filename, sizeof(SR_8), file_rec.filename_size, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			sr_cls_file_add_rule(filename, process, "*", file_rec.rulenum, 1);
			sr_cls_rule_add(SR_FILE_RULES, file_rec.rulenum, file_rec.action.actions_bitmap, SR_FILEOPS_READ, file_rec.max_rate, file_rec.rate_action, file_rec.action.log_target, file_rec.action.email_id, file_rec.action.phone_id, file_rec.action.skip_rulenum);
			break;
			}
		case CONFIG_CAN_RULE: {
			struct sr_can_record	can_rec;
			if (1 != fread(&can_rec, sizeof(can_rec), 1, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			memset(process, 0, 4096);
			if (can_rec.process_size != fread(&process, sizeof(SR_8), can_rec.process_size, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			sr_cls_canid_add_rule(can_rec.msg_id, process, "*", can_rec.rulenum);
			sr_cls_rule_add(SR_CAN_RULES, can_rec.rulenum, can_rec.action.actions_bitmap, 0, can_rec.max_rate, can_rec.rate_action, can_rec.action.log_target, can_rec.action.email_id, can_rec.action.phone_id, can_rec.action.skip_rulenum);
			break;
			}
		case CONFIG_PHONE_ENTRY: {
			struct sr_phone_record	phone_rec;
			if (1 != fread(&phone_rec, sizeof(phone_rec), 1, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			printf ("msg type = phone entry\n");
			printf ("phone_id = %d\n", phone_rec.phone_id);
			printf ("phone_number = %s\n", phone_rec.phone_number);
			break;
			}
		case CONFIG_EMAIL_ENTRY: {
			struct sr_email_record	email_rec;
			char					email[256];
			if (1 != fread(&email_rec, sizeof(email_rec), 1, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			memset(email, 0, 256);
			if (email_rec.email_size != fread(&email, sizeof(SR_8), email_rec.email_size, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			printf ("msg type = email entry\n");
			printf ("email_id = %d\n", email_rec.email_id);
			printf ("email = %s\n", email);
			break;
			}
		case CONFIG_LOG_TARGET: {
			struct sr_log_record	log_rec;
			char					log_target[256];
			if (1 != fread(&log_rec, sizeof(log_rec), 1, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			memset(log_target, 0, 256);
			if (log_rec.log_size != fread(&log_target, sizeof(SR_8), log_rec.log_size, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			printf ("msg type = log target\n");
			printf ("log_id = %d\n", log_rec.log_id);
			printf ("log target = %s\n", log_target);
			break;
			}
		default:
			fclose (conf_file);
			return SR_FALSE;
			break;
		};
	} /* end of configuration file reached */

	fclose (conf_file);
	return SR_TRUE;
}

SR_U32 handle_rule_ut(char *filename, char *exec, char *user, SR_U32 rulenum, SR_U16 actions, SR_8 file_ops)
{
	printf("**** Arik in handle_rule file:%s rule#%d exec:%s user:%s actions:%x file_ops:%x \n", 
		filename, rulenum, exec, user, actions, file_ops);

 	return SR_SUCCESS;
}

#if 0
static void file_hash_ut(void)
{
 	SR_32 rc;

	printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX file hash ut \n");
	rc =  sr_file_hash_update_rule("/var/log/arik", "*", "*", 1,  1, 2);
	printf("Insert /var/log/arik rc:%d \n", rc);
	rc =  sr_file_hash_update_rule("/var/log/kuku", "*", "*", 1,  1, 2);
	printf("Insert /var/log/arik rc:%d \n", rc);
	rc =  sr_file_hash_update_rule("/var/log/arik", "*", "*", 2,  1, 2);
	printf("Insert /var/log/arik rc:%d \n", rc);
	rc =  sr_file_hash_update_rule("/var/log/arik", "lulu", "pupu", 3,  4, 5);
	printf("Insert /var/log/arik rc:%d \n", rc);
	rc =  sr_file_hash_update_rule("/var/gol/ukuk", "*", "*", 1,  1, 2);
	printf("Insert /var/log/arik rc:%d \n", rc);
	sr_file_hash_print();

	rc = sr_file_hash_exec_for_file("/var/log/arik", handle_rule_ut);
	printf("--- after Get /var/log/arik file rc%d ...\n", rc);

	rc = sr_file_hash_delete_all();
        printf("After delete_all rc:%d \n", rc);
        sr_file_hash_print();
	
	printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX END file hash ut \n");
}
#endif	

SR_BOOL config_ut(void)
{
	struct sr_file_entry		file_rec = {0};
	struct sr_net_entry			net_rec = {0};
#if 0
	struct sr_can_entry			can_rec = {0};
	struct sr_phone_record		phone_rec = {0};
	struct sr_email_entry		email_rec = {0};
	struct sr_log_entry			log_rec = {0};
#endif

#if 0
	net_rec.rulenum = 80;
	net_rec.src_addr = 0x0a0a0a00;
	net_rec.src_netmask = 0x0;
	//net_rec.src_netmask = 0xFFFFFFFF;
	net_rec.dst_addr = 0x0a0a0a00;
	net_rec.dst_netmask = 0xFFFFFFFF;
	net_rec.dst_netmask = 0x0;
	net_rec.action.actions_bitmap = SR_CLS_ACTION_DROP;
	net_rec.action.email_id = 7;
	net_rec.src_port = 0;
	net_rec.dst_port = 22;
	net_rec.proto = SR_PROTO_TCP;
	net_rec.action.log_target = 8;
	net_rec.action.phone_id = 4;
	//net_rec.action.skip_rulenum = 258;
        //net_rec.uid = 13579;
	strncpy(net_rec.process, "/home/arik/arik/client", strlen("/home/arik/arik/client"));
	//strncpy(net_rec.process, "*", strlen("*"));
	net_rec.process_size = strlen(net_rec.process);
	write_config_record(&net_rec, CONFIG_NET_RULE);
#endif

	net_rec.rulenum = 85;
	net_rec.src_addr = 0xc0a8020d;
	net_rec.src_netmask = 0xFFFFFFFF;
	net_rec.dst_addr = 0xc0a80114;
	net_rec.dst_netmask = 0xFFFFFFFF;
	net_rec.action.actions_bitmap = SR_CLS_ACTION_DROP;
	net_rec.action.email_id = 7;
	net_rec.src_port = 0;
	net_rec.dst_port = 22;
	net_rec.proto = SR_PROTO_TCP;
	net_rec.action.log_target = 8;
	net_rec.action.phone_id = 4;
	//net_rec.action.skip_rulenum = 258;
        //net_rec.uid = 13579;
	strncpy(net_rec.process, "/home/arik/arik/server", strlen("/home/arik/arik/server"));
	//strncpy(net_rec.process, "*", strlen("*"));
	net_rec.process_size = strlen(net_rec.process);
	write_config_record(&net_rec, CONFIG_NET_RULE);
	
	file_rec.rulenum=457;	
	file_rec.action.actions_bitmap=SR_CLS_ACTION_DROP;		
	file_rec.uid=-1;
	strncpy(file_rec.filename, "/home/arik/arik/log", strlen("/home/arik/arik/log"));
	strncpy(file_rec.process, "/bin/cat", strlen("/bin/cat"));
	file_rec.process_size = strlen(file_rec.process);
	file_rec.filename_size = strlen(file_rec.filename);
	write_config_record(&file_rec, CONFIG_FILE_RULE);

#if 0
	file_rec.rulenum=404;	
	file_rec.action.actions_bitmap=SR_CLS_ACTION_DROP;		
	file_rec.uid=-1;
	strncpy(file_rec.filename, "/home/arik/arik/log1", strlen("/home/arik/arik/log1"));
	//strncpy(file_rec.process, "/bin/cat", strlen("/bin/cat"));
	strncpy(file_rec.process, "*", strlen("*"));
	file_rec.process_size = strlen(file_rec.process);
	file_rec.filename_size = strlen(file_rec.filename);
	write_config_record(&file_rec, CONFIG_FILE_RULE);
		
        can_rec.rulenum=40;	
        can_rec.msg_id=0x123;		
        can_rec.action.actions_bitmap=SR_CLS_ACTION_DROP;	
        can_rec.uid=20;
        strncpy(can_rec.process, "/usr/bin/cansend", strlen("/usr/bin/cansend"));
        //strncpy(can_rec.process, "*", strlen("*"));
	can_rec.process_size = strlen(can_rec.process);
	write_config_record(&can_rec, CONFIG_CAN_RULE);

/*
	//phone_rec.phone_id=17;
	//strncpy(phone_rec.phone_number, "054-7653982", strlen("054-7653982"));
	//write_config_record(&phone_rec, CONFIG_PHONE_ENTRY);

	//email_rec.email_id=38;
	//strncpy(email_rec.email, "shayd@saferide.io", strlen("shayd@saferide.io"));
	//email_rec.email_size = strlen(email_rec.email);
	//write_config_record(&email_rec, CONFIG_EMAIL_ENTRY);
	
	//log_rec.log_id=19;
	//strncpy(log_rec.log_target, "/var/log/syslog", strlen("/var/log/syslog"));
	//log_rec.log_size = strlen(log_rec.log_target);
	//write_config_record(&log_rec, CONFIG_LOG_TARGET);
*/

#endif
	//file_hash_ut();
	//read_config_file();

	/* Load DB from confd */
        read_config_db();
        /* Handle commit evenets from confd */
	handle_commit_events();

	return SR_TRUE;
}
