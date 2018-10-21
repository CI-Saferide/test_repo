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
#include "sr_ver.h"

static SR_BOOL is_run;
static pthread_t t;
static int g_fd;

static void handle_ver_cmd(int fd)
{
	char out_buf[512] = {};

	sprintf(out_buf, "version is %d.%d (%s)", VSENTRY_VER_MAJOR, VSENTRY_VER_MINOR, VSENTRY_VER_BUILD);
	if (write(fd, out_buf, strlen(out_buf) + 1) < strlen(out_buf) + 1)
		printf("write error\n");
}

static void notify_apply(void)
{
	char syncbuf[2];

	// Snc 
	syncbuf[0] = SR_CLI_END_OF_TRANSACTION;
        if (write(g_fd, syncbuf, 1) < 1)
                printf("Failed writing sync buf\n");
}

static SR_32 handle_data(char *buf, SR_32 fd)
{
	if (!memcmp(buf, "cli_load", strlen("cli_load")))
		sr_engine_cli_load(fd);
	if (!memcmp(buf, "cli_commit", strlen("cli_commit")))
		sr_engine_cli_commit(fd);
	if (!memcmp(buf, "wl_learn", strlen("wl_learn")))
		sr_white_list_set_mode(SR_WL_MODE_LEARN, NULL);
	if (!memcmp(buf, "wl_apply", strlen("wl_apply"))) {
		g_fd = fd;
		sr_white_list_set_mode(SR_WL_MODE_APPLY, notify_apply);
	}
	if (!memcmp(buf, "wl_print", strlen("wl_ptint"))) {
		sr_engine_cli_print(fd);
	}
	if (!memcmp(buf, "wl_reset", strlen("wl_reset")))
		sr_white_list_reset();
	if (!memcmp(buf, "sp_learn", strlen("sp_learn")))
		sr_stat_analysis_learn_mode_set(SR_STAT_MODE_LEARN);
	if (!memcmp(buf, "sp_apply", strlen("sp_apply")))
		sr_stat_analysis_learn_mode_set(SR_STAT_MODE_PROTECT);
	if (!memcmp(buf, "sp_off", strlen("sp_off")))
		sr_stat_analysis_learn_mode_set(SR_STAT_MODE_OFF);
	if (!memcmp(buf, "sr_ver", strlen("sr_ver")))
		handle_ver_cmd(fd);

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
