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
#define PAD_SIZE 	4096

static void *dbmem = NULL;
static int dbmem_size = 0;
static void *execmem = NULL;
static int execsize = 0;
static FILE *db_file = NULL;
static int (*cls_event)(vsentry_ev_type_e ev_type, vsentry_event_t *event, bool atomic) = NULL;

/* this function will open the dbfile. if it does not exist, it will creat it */
static int init_db_file(char *dbfile)
{
	struct stat sb;

	/* check if the db file exist and its size. if not, re/create the file
	 * with the heap in it */
	if ((stat(dbfile, &sb) == -1) || (sb.st_size != SHMEM_BUFFER_SIZE)) {
		unsigned char pad[PAD_SIZE];
		int size = SHMEM_BUFFER_SIZE;

		db_file = fopen(dbfile, "w+");
		if (!db_file) {
			fprintf(stderr, "failed to create db file\n");
			return VSENTRY_ERROR;
		}

		memset(pad, 0, PAD_SIZE);

		while (size) {
			fwrite(pad, 1, PAD_SIZE, db_file);
			size -= PAD_SIZE;
		}

		fclose(db_file);

		fprintf(stdout, "created new db file %s\n", dbfile);
	}

	return VSENTRY_SUCCESS;
}

/* this function will map the dbfile to this process memory */
static int init_db_mem(char *dbfile)
{
	struct stat st;
	int fd;

	/* open (may create) the db file */
	if (init_db_file(dbfile) != VSENTRY_SUCCESS) {
		fprintf(stderr, "failed to init db file\n");
		return VSENTRY_ERROR;
	}

	db_file = fopen(dbfile, "r+");
	if (!db_file) {
		fprintf(stderr, "failed to open db file %s. error %s\n",
				dbfile, strerror(errno));
		return VSENTRY_ERROR;
	}

	fseek(db_file, 0L, SEEK_SET);

	fd = fileno(db_file);
	if (fd <= 0) {
		fprintf(stderr, "failed extract dbfile fd\n");
		return VSENTRY_ERROR;
	}

	if (stat(dbfile, &st)) {
		fprintf(stderr, "failed to run stat on %s\n", dbfile);
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
		dbmem, dbfile);

	return VSENTRY_SUCCESS;
}

static int init_execmem(char *execfile)
{
	struct stat st;
	FILE *bin_file = NULL;

	/* check if execfile exist */
	if (stat(execfile, &st)) {
		fprintf(stderr, "failed to run stat on %s\n", execfile);
		return VSENTRY_ERROR;
	}

	execsize = st.st_size;

	/* allocate exec memory and write the execfile to it */
	execmem = mmap(NULL, execsize, (PROT_READ|PROT_WRITE|PROT_EXEC),
		(MAP_ANON | MAP_SHARED| MAP_LOCKED) , -1, 0);
	if (!execmem) {
		fprintf(stderr, "failed to mmap\n");
		return VSENTRY_ERROR;
	}

	/* copy the bin file to the execution memory */
	bin_file = fopen(execfile, "r");
	if (!bin_file) {
		fprintf(stderr, "failed to open execfile %s. error %s\n",
				execfile, strerror(errno));
		return VSENTRY_ERROR;
	}

	if (fread(execmem, 1, execsize, bin_file) != execsize) {
		fprintf(stderr, "failed to copy bin file\n");
		return VSENTRY_ERROR;
	}

	fclose(bin_file);

	cls_event = execmem;

	fprintf(stdout, "execution memory %p initialized successfully (file %s)\n", execmem, execfile);

	return VSENTRY_SUCCESS;
}

static int test(void)
{
	vsentry_event_t ev;

	memset(&ev, 0, sizeof(vsentry_event_t));

	return cls_event(VSENTRY_CAN_EVENT, &ev, false);
}

int main(int argc, char **argv)
{
	int opt;
	int ret = VSENTRY_SUCCESS;
	char *execfile = EXEC_FILE;
	char *dbfile = DB_FILE;
	bool debug = false;
	unsigned int mode = CLS_MODE_ENFORCE;

	while ((opt = getopt (argc, argv, "e:f:h")) != -1) {
		switch (opt) {
		case 'e':
			execfile = optarg;
			break;

		case 'f':
			dbfile = optarg;
			break;

		case 'h':
			fprintf(stderr, "usage: %s [-e execfile] [-f dbfile] [-d][-h]\n", argv[0]);
			fprintf(stderr, "      -e execfile. specify the binfile to execute\n");
			fprintf(stderr, "      -f dbfile. specify the database file\n");
			fprintf(stderr, "      -h : print this help\n");
			exit(EXIT_SUCCESS);
			break;
		default:
			break;
		}
	}

	fprintf(stdout, "using execfile %s\n", execfile);
	fprintf(stdout, "using dbfile %s\n", dbfile);

	ret = init_execmem(execfile);
	if (ret != VSENTRY_SUCCESS) {
		fprintf(stderr, "failed to execution memory\n");
		goto exit_err;
	}

	/* open the db mem */
	ret = init_db_mem(dbfile);
	if (ret != VSENTRY_SUCCESS) {
		fprintf(stderr, "failed to init db file\n");
		goto exit_err;
	}

	cls_event(VSENTRY_REGISTER_PRINTF, (void*)printf, false);

	/* init classifier database used by binary */
	ret = cls_event(VSENTRY_CLASIFFIER_INIT, dbmem, false);
	if (ret != VSENTRY_SUCCESS) {
		fprintf(stderr, "failed to init standalone classifier\n");
		goto exit_err;
	}

	cls_event(VSENTRY_CLASIFFIER_SET_MODE, (vsentry_event_t*)&mode, false);

	test();

exit_err:
	if (debug) {
		if (db_file) {
			fsync(fileno(db_file));
			fclose(db_file);
		}

		if (dbmem)
			munmap(dbmem, dbmem_size);

		if (execmem)
			munmap(execmem, execsize);
	}

	exit(ret);
}

