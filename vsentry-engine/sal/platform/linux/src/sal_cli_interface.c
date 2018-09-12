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
#include "sr_engine_cli.h"

static SR_BOOL is_run;
static pthread_t t;

static SR_32 handle_data(char *buf, SR_32 fd)
{
	if (!memcmp(buf, "cli_load", strlen("cli_load")))
		sr_engine_cli_load(fd);
	if (!memcmp(buf, "cli_commit", strlen("cli_commit")))
		sr_engine_cli_commit(fd);

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
