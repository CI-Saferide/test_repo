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
#include "sr_white_list.h"
#include "sr_control.h"
#include "sr_config.h"
#include "redis_mng.h"

static int g_fd;
static redisContext *c;

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

static void cli_print_cb(char *buf) {
	char print_buf[512];
	SR_32 n, rc;
	
	sprintf(print_buf, "%s%c", buf, SR_CLI_END_OF_ENTITY);
	n = strlen(print_buf);
	rc = write(g_fd, print_buf, n);
	if (rc < n) {
                printf("Write in cli print cb failed \n");
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=Write in cli print cb failed.",REASON);
	}
}

void sr_engine_cli_print(SR_32 fd)
{
	char buf[256];
	SR_32 n;

	snprintf(buf, 256, "\nLearning: \n%c:", SR_CLI_END_OF_ENTITY);
	n = strlen(buf);
	if (write(fd, buf, n) < n) {
		printf("Write in cli print failed \n");
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=Write in cli print failed.",REASON);
	}

	white_list_print_cb_register(cli_print_cb);
	white_list_ip_print_cb_register(cli_print_cb);

	g_fd = fd;
  	sr_white_list_hash_print();
	sprintf(buf, "\n IP Learning:\n%c", SR_CLI_END_OF_ENTITY);
	n = strlen(buf);
	if (write(fd, buf, n) < n) {
		printf("Write in cli print failed \n");
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=Write in cli print failed.",REASON);
	}
	sr_white_list_ip_print();
	sprintf(buf, "%c", SR_CLI_END_OF_TRANSACTION);
	if (write(fd, buf, 1) < 1) {
		printf("Write in cli print failed, end transaction \n");
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=Write in cli print failed.",REASON);
	}
	printf("print connection object:\n");
	sr_control_util(SR_CONTROL_PRINT);
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

SR_32 sr_engine_cli_commit(SR_32 fd)
{
	SR_32 rc = SR_SUCCESS;

	sr_engine_get_db_lock();
	c = redis_mng_session_start();
	if (!c) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=redis session start failed",REASON);
		rc = SR_ERROR;
		goto out;
	}

	if (redis_mng_load_db(c, SR_TRUE, sr_config_handle_rule, sr_config_handle_action) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=load db failed",REASON);
		rc = SR_ERROR;
		goto out;
	}

out:
	if (c)
		redis_mng_session_end(c);
	sr_engine_get_db_unlock();

	return rc;
}


