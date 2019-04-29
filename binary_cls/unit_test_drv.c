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

static int drv_fd = 0;

int bin_cls_reload(char *exec_file_name)
{
	/* config file is ready, lets update the kernel */
	if (ioctl(drv_fd, VSENTRY_IOCTL_UPDATE_EXECFILE, exec_file_name) != 0) {
		fprintf(stderr, "failed to update execfile %s: %s (%d)\n", exec_file_name, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	return VSENTRY_SUCCESS;
}

int bin_cls_update(char *db_file_name)
{
	/* DB file is ready, lets update the kernel */
	if (ioctl(drv_fd, VSENTRY_IOCTL_UPDATE_DBFILE, db_file_name) != 0) {
		fprintf(stderr, "failed to update dbfile %s: %s (%d)\n", db_file_name, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	return VSENTRY_SUCCESS;
}

int bin_cls_db_copy(char *db_file_name)
{
	if (ioctl(drv_fd, VSENTRY_IOCTL_COPY_DBFILE, db_file_name) != 0) {
		fprintf(stderr, "failed to copy db to  dbfile %s: %s (%d)\n", db_file_name, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	return VSENTRY_SUCCESS;
}

int bin_cls_get_state(struct vsentry_state *state)
{
	if (ioctl(drv_fd, VSENTRY_IOCTL_GET_STATE, state) != 0) {
		fprintf(stderr, "failed to ioctl %s: %s (%d)\n", BIN_CLS_DRV, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	fprintf(stdout, "classifier is %s\n", state->enabled?"enabled":"disabled");
	switch (state->mode) {
	case VSENTRY_MODE_ENFORCE:
		fprintf(stdout, "classifier mode is enforce\n");
		break;
	case VSENTRY_MODE_PERMISSIVE:
		fprintf(stdout, "classifier mode is permissive\n");
		break;
	case VSENTRY_MODE_LEARN:
		fprintf(stdout, "classifier mode is learn\n");
		break;
	default:
		fprintf(stderr, "unknown mode\n");
		break;
	}

	switch (state->file_cls_mode) {
	case FILE_CLS_MODE_STR:
		fprintf(stdout, "file classifier mode is string\n");
		break;
	case FILE_CLS_MODE_INODE:
		fprintf(stdout, "file classifier mode is inode\n");
		break;
	default:
		fprintf(stderr, "unknown mode\n");
		break;
	}

	fprintf(stdout, "classifier binary is %s present\n", state->cls_present?"":"not");
	fprintf(stdout, "classifier database is %s present\n", state->cls_present?"":"not");

	return VSENTRY_SUCCESS;
}

int bin_cls_set_mode(void)
{
	char input[3];
	unsigned int mode = -1;

	fprintf(stdout, "enter mode (e-enforce, p-permissive l-learn): ");

	if (fgets(input, 3, stdin) == NULL)
		return VSENTRY_ERROR;

	switch (input[0]) {
	case 'e':
		mode = VSENTRY_MODE_ENFORCE;
		break;
	case 'p':
		mode = VSENTRY_MODE_PERMISSIVE;
		break;
#ifdef ENABLE_LEARN
	case 'l':
		mode = VSENTRY_MODE_LEARN;
		break;
#endif
	default:
		fprintf(stderr, "invalid mode\n");
		return VSENTRY_ERROR;
	}

	if (ioctl(drv_fd, VSENTRY_IOCTL_SET_MODE, &mode) != 0) {
		fprintf(stderr, "failed to set mode %s: %s (%d)\n", BIN_CLS_DRV, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	return VSENTRY_SUCCESS;
}

int bin_cls_set_file_mode(void)
{
	char input[3];
	unsigned int mode = -1;

	fprintf(stdout, "enter mode (s-string, i-inode): ");

	if (fgets(input, 3, stdin) == NULL)
		return VSENTRY_ERROR;

	switch (input[0]) {
	case 'i':
		mode = FILE_CLS_MODE_INODE;
		break;
	case 's':
		mode = FILE_CLS_MODE_STR;
		break;
	default:
		fprintf(stderr, "invalid mode\n");
		return VSENTRY_ERROR;
	}

	if (ioctl(drv_fd, VSENTRY_IOCTL_FILE_CLS_MODE, &mode) != 0) {
		fprintf(stderr, "failed to set file mode %s: %s (%d)\n", BIN_CLS_DRV, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	return VSENTRY_SUCCESS;
}

int bin_cls_enable(bool enable, char *exec_file_name, char *db_file_name)
{
	unsigned int vs_enable = enable;

	if (ioctl(drv_fd, VSENTRY_IOCTL_SET_ENABLE, &vs_enable) != 0) {
		fprintf(stderr, "failed to %s %s: %s (%d)\n", enable?"enable":"disable",
				BIN_CLS_DRV, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	fprintf(stdout, "vsentry %s\n", enable?"enabled":"disabled");

	return VSENTRY_SUCCESS;
}

static void *dbmem = NULL;
static int dbmem_size = 0;
static FILE *db_file = NULL;

static int init_db_mem(char *dbfile_name)
{
	struct stat st;
	int fd;

	db_file = fopen(dbfile_name, "r+");
	if (!db_file) {
		fprintf(stderr, "failed to open db file %s. error %s\n",
				dbfile_name, strerror(errno));
		return VSENTRY_ERROR;
	}

	fseek(db_file, 0L, SEEK_SET);

	fd = fileno(db_file);
	if (fd <= 0) {
		fprintf(stderr, "failed extract dbfile fd\n");
		return VSENTRY_ERROR;
	}

	if (stat(dbfile_name, &st)) {
		fprintf(stderr, "failed to run stat on %s\n", dbfile_name);
		return VSENTRY_ERROR;
	}

	/* map file to memory */
	/* MAP_LOCKED is marked as it result an error when mapping large files */
	dbmem = mmap(NULL, st.st_size, (PROT_READ | PROT_WRITE),
		(MAP_SHARED/*| MAP_LOCKED*/ ) ,fd, 0);
	if (dbmem == MAP_FAILED) {
		fprintf(stderr, "failed to alloc dbmem. %s\n", strerror(errno));
		return VSENTRY_ERROR;
	}

	dbmem_size = st.st_size;

	fprintf(stdout, "database memory %p mmaped successfully (file %s)\n",
		dbmem, dbfile_name);

	return VSENTRY_SUCCESS;
}

int print_db(char *dbfile_name)
{
	int ret = init_db_mem(dbfile_name);
	if (ret != VSENTRY_SUCCESS)
		goto print_exit;

	/* init classifier database used by binary */
	ret = cls_handle_event(VSENTRY_CLASIFFIER_INIT, dbmem);
	if (ret != VSENTRY_SUCCESS) {
		fprintf(stderr, "failed to init standalone classifier\n");
		goto print_exit;
	}

	cls_handle_event(VSENTRY_REGISTER_PRINTF, (void*)printf);
	cls_handle_event(VSENTRY_PRINT_INFO, NULL);

	ioctl(drv_fd, VSENTRY_IOCTL_PRINT_INFO, NULL);
print_exit:
	if (db_file)
		fclose(db_file);

	if (dbmem)
		munmap(dbmem, dbmem_size);

	return ret;
}

int main(int argc, char **argv)
{
	bool run = true;
	bool enable = true;
	char *db_file_name = DB_FILE;
	char *exec_file_name = EXEC_FILE;
	int opt;
	struct vsentry_state state;

	while ((opt = getopt (argc, argv, "e:f:h")) != -1) {
		switch (opt) {
		case 'e':
			exec_file_name = optarg;
			break;
		case 'f':
			db_file_name = optarg;
			break;

		case 'h':
			fprintf(stderr, "usage: %s [-e execfile] [-f dbfile] -h]\n", argv[0]);
			fprintf(stderr, "	-e execfile. specify the binfile to execute\n");
			fprintf(stderr, "	-f dbfile. specify the database file\n");
			fprintf(stderr, "	-h : print this help\n");
			exit(EXIT_SUCCESS);
			break;
		default:
			break;
		}
	}

	/* config file is ready, lets update the kernel */
	drv_fd = open(BIN_CLS_DRV, O_RDWR|O_SYNC);
	if (drv_fd < 0) {
		fprintf(stderr, "failed to open %s: %s (%d)\n", BIN_CLS_DRV, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	if (bin_cls_get_state(&state) != VSENTRY_SUCCESS)
		return VSENTRY_ERROR;

	enable = state.enabled;

	while (run) {
		char input[3];

		if (fgets(input, 3, stdin) == NULL)
			continue;

		switch(input[0]) {
		case 'b':
			run = 0;
			break;
		case 'r':
			bin_cls_reload(exec_file_name);
			break;
		case 'u':
			bin_cls_update(db_file_name);
			break;
		case 'e':
			bin_cls_enable(enable?false:true, exec_file_name, db_file_name);
			enable = enable?false:true;
			break;
		case 'p':
			print_db(db_file_name);
			break;
		case 'c':
			bin_cls_db_copy(db_file_name);
			break;
		case 'g':
			bin_cls_get_state(&state);
			break;
		case 'm':
			bin_cls_set_mode();
			break;
		case 's':
			bin_cls_set_file_mode();
			break;
		case 'h':
			fprintf(stdout, "b-break, r-reload cls, u-update db, e-toggle enable, p-print db, c-copy from kernel db, g-get mode, m-set mode\n");
			break;
		default:
			break;
		}
	}

	return 0;
}

