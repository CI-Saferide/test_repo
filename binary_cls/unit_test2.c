#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <malloc.h>
#include <linux/vsentry/vsentry.h>
#include <linux/vsentry/vsentry_drv.h>
#include "classifier.h"

#define DB_FILE 	"/etc/vsentry/db.mem"
#define EXEC_FILE 	"/etc/vsentry/cls.bin"
#define BIN_CLS_DRV 	"/dev/vs_drv"

#define PAD_SIZE 	4096

int bin_cls_reload(void)
{
	int ret, drv_fd;

	/* config file is ready, lets update the kernel */
	drv_fd = open(BIN_CLS_DRV, O_RDWR|O_SYNC);
	if (drv_fd < 0) {
		fprintf(stderr, "failed to open %s: %s (%d)\n", BIN_CLS_DRV, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	ret = ioctl(drv_fd, VSENTRY_IOCTL_UPDATE_EXECFILE, EXEC_FILE);
	if (ret != 0)
		fprintf(stderr, "failed to update execfile %s: %s (%d)\n", EXEC_FILE, strerror(errno), errno);

	if (drv_fd)
		close(drv_fd);

	if (ret)
		return VSENTRY_ERROR;

	return VSENTRY_SUCCESS;
}

int bin_cls_update(void)
{
	int ret, drv_fd = 0;

	/* DB file is ready, lets update the kernel */
	drv_fd = open(BIN_CLS_DRV, O_RDWR|O_SYNC);
	if (drv_fd < 0) {
		fprintf(stderr, "failed to open %s: %s (%d)\n", BIN_CLS_DRV, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	ret = ioctl(drv_fd, VSENTRY_IOCTL_UPDATE_DBFILE, DB_FILE);
	if (ret != 0)
		fprintf(stderr, "failed to update dbfile %s: %s (%d)\n", DB_FILE, strerror(errno), errno);

	close(drv_fd);

	if (ret)
		return VSENTRY_ERROR;

	return VSENTRY_SUCCESS;
}

int bin_cls_enable(bool enable)
{
	int ret, drv_fd;
	unsigned int vs_enable = enable;
	struct vsentry_state state;

	drv_fd = open(BIN_CLS_DRV, O_RDWR|O_SYNC);
	if (drv_fd < 0) {
		fprintf(stderr, "failed to open %s: %s (%d)\n", BIN_CLS_DRV, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	ret = ioctl(drv_fd, VSENTRY_IOCTL_GET_STATE, &state);
	if (ret != 0) {
		fprintf(stderr, "failed to ioctl %s: %s (%d)\n", BIN_CLS_DRV, strerror(errno), errno);
		goto enable_exit;
	}

	close(drv_fd);

	if (state.enabled == enable) {
		fprintf(stdout, "already %s\n", enable?"enabled":"disabled");
		goto enable_exit;
	}

	if (enable) {
		if (!state.cls_present) {
			ret = bin_cls_reload();
			if (ret != VSENTRY_SUCCESS) {
				fprintf(stderr, "failed to update execfile %s\n", EXEC_FILE);
				goto enable_exit;
			}
		}

		if (!state.db_present) {
			ret = bin_cls_update();
			if (ret != VSENTRY_SUCCESS) {
				fprintf(stderr, "failed to update dbfile %s\n", DB_FILE);
				goto enable_exit;
			}
		}
	}

	drv_fd = open(BIN_CLS_DRV, O_RDWR|O_SYNC);
	if (drv_fd < 0) {
		fprintf(stderr, "failed to open %s: %s (%d)\n", BIN_CLS_DRV, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	ret = ioctl(drv_fd, VSENTRY_IOCTL_SET_ENABLE, &vs_enable);
	if (ret != 0) {
		fprintf(stderr, "failed to %s %s: %s (%d)\n", enable?"enable":"disable",
				BIN_CLS_DRV, strerror(errno), errno);
	}

enable_exit:
	close(drv_fd);

	if (ret)
		return VSENTRY_ERROR;

	return VSENTRY_SUCCESS;
}

int main(int argc, char **argv)
{
	bool run = true;
	bool enable = true;

	while (run) {
		unsigned int input = getchar();
		switch(input) {
		case 'b':
			run = 0;
			break;
		case 'r':
			bin_cls_reload();
			break;
		case'u':
			bin_cls_update();
			break;
		case 'e':
			bin_cls_enable(enable);
			enable = enable?false:true;
			break;
		}
	}

	return 0;
}

