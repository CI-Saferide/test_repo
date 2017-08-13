/* sr_config.c */

#include "sr_config.h"
#include "sr_cls_network_common.h"
#include "sr_cls_port_control.h"
#include "sr_cls_network_control.h"
#include "sr_cls_rules_control.h"
#include "sr_cls_canbus_control.h"
#include "sr_cls_file_control.h"
#include <arpa/inet.h> // TODO: take care of the agnostic part

static SR_8* filename = "sr_config.cfg";

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

SR_BOOL read_config_file (void)
{
	FILE* 					conf_file;
	char					process[4096];
	enum sr_header_type		rec_type;
	conf_file = fopen(filename,"rb");
	
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
			sr_cls_port_add_rule(net_rec.src_port, process, net_rec.rulenum, SR_DIR_SRC, net_rec.proto);
			sr_cls_port_add_rule(net_rec.dst_port, process, net_rec.rulenum, SR_DIR_DST, net_rec.proto);
			sr_cls_add_ipv4(htonl(net_rec.src_addr), process, htonl(net_rec.src_netmask), net_rec.rulenum, SR_DIR_SRC);
			sr_cls_add_ipv4(htonl(net_rec.dst_addr), process, htonl(net_rec.dst_netmask), net_rec.rulenum, SR_DIR_DST);
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
			sr_cls_file_add_rule(filename, process, file_rec.rulenum, 1);
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
			sr_cls_canid_add_rule(can_rec.msg_id, process, can_rec.rulenum);
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

SR_BOOL config_ut(void)
{
/*
	struct sr_file_entry		file_rec = {0};
	struct sr_net_entry			net_rec = {0};
	struct sr_can_entry			can_rec = {0};
	struct sr_phone_record		phone_rec = {0};
	struct sr_email_entry		email_rec = {0};
	struct sr_log_entry			log_rec = {0};

	net_rec.rulenum = 80;
	net_rec.src_addr = 0x0a0a0a00;
	net_rec.src_netmask = 0x0;
	net_rec.dst_addr = 0x0a0a0a00;
	net_rec.dst_netmask = 0x0;
	net_rec.action.actions_bitmap = SR_CLS_ACTION_DROP;
	net_rec.action.email_id = 7;
	net_rec.src_port = 0;
	net_rec.dst_port = 7777;
	net_rec.proto = SR_PROTO_TCP;
	net_rec.action.log_target = 8;
	net_rec.action.phone_id = 4;
	//net_rec.action.skip_rulenum = 258;
        //net_rec.uid = 13579;
	strncpy(net_rec.process, "/home/arik/arik/client", strlen("/home/arik/arik/client"));
	//strncpy(net_rec.process, "*", strlen("*"));
	net_rec.process_size = strlen(net_rec.process);
	write_config_record(&net_rec, CONFIG_NET_RULE);

	net_rec.rulenum = 85;
	net_rec.src_addr = 0x0a0a0a00;
	net_rec.src_netmask = 0x0;
	net_rec.dst_addr = 0x0a0a0a00;
	net_rec.dst_netmask = 0x0;
	net_rec.action.actions_bitmap = SR_CLS_ACTION_DROP;
	net_rec.action.email_id = 7;
	net_rec.src_port = 7778;
	net_rec.dst_port = 0;
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

	read_config_file();
	return SR_TRUE;
}
