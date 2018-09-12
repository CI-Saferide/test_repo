#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "sal_cli_interface.h"
#include "sr_log.h"
#include "sr_types.h"
#include "sr_white_list.h"
#include "sr_stat_analysis.h"
#include "sr_control.h"
#include "sr_db.h"
#include "sr_db_file.h"
#include "sr_db_ip.h"
#include "sr_db_can.h"

static SR_BOOL is_run;
static pthread_t t;

static void handle_cli_load(SR_32 fd)
{
	action_dump(fd);
	file_rule_dump_rules(fd);
	ip_rule_dump_rules(fd);
	can_rule_dump_rules(fd);
	write(fd, "&", 1);
}

static void handle_cli_commit(SR_32 fd)
{
	SR_U32 len, ind;
	char cval;
	char buf[10000];

	// Snc 
	write(fd, "&", 1);

	buf[0] = 0;
	ind = 0;
	for (;;) {
		len = read(fd, &cval, 1);
		if (!len) {
			printf("Failed reading from socket");
			return;
		}
		switch (cval) {
			case '&': /* Finish load */
                                goto out;
                        case '#': /* Finish rule */
                                buf[ind] = 0;
                                printf("Got buffer:%s: \n", buf);
                                buf[0] = 0;
                                ind = 0;
                                break;
                        default:
                                buf[ind++] = cval;
                                break;
                }
        }

out:
	return;
}

static SR_32 handle_data(char *buf, SR_32 fd)
{
	printf("Got buf:%s: \n", buf);
	if (!memcmp(buf, "cli_load", strlen("cli_load")))
		handle_cli_load(fd);
	if (!memcmp(buf, "cli_commit", strlen("cli_commit")))
		handle_cli_commit(fd);

	return SR_SUCCESS;
}

static SR_BOOL is_run_cb(void)
{
	return is_run;
}

static void *cli_interface_server(void *p)
{
	SR_32 rc;

	rc = sal_linux_local_interface(SR_CLI_INTERFACE_FILE, handle_data, is_run_cb);
	if (rc != SR_SUCCESS) {
		printf("linux local interface failed for cli \n");
	}

	return NULL;
}

SR_32 sal_cli_interface_init(void)
{
	is_run = SR_TRUE;

	if (pthread_create(&t, NULL, cli_interface_server, &is_run) != 0) {
		printf("pthread_create: %s\n", strerror(errno));
        	return SR_ERROR;
	}

	return SR_SUCCESS;
}

void sal_cli_interface_uninit(void)
{
	is_run = SR_FALSE;
	pthread_cancel(t);
}
