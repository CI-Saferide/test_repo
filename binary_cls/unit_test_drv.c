#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <malloc.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>
#include <linux/vsentry/vsentry.h>
#include <linux/vsentry/vsentry_drv.h>
#include "classifier.h"

#define DB_FILE 	"/etc/vsentry/db.mem"
#define EXEC_FILE 	"/etc/vsentry/cls.bin"
#define BIN_CLS_DRV 	"/dev/vs_drv"

#define PAD_SIZE 	4096

static int drv_fd = 0;

static struct vsentry_genl_info genl_info;

static void generate_can_log_extention(char *dst, int len, bool allow, vsentry_event_t *can_ev)
{
	snprintf(dst, len, "can %s: msgid 0x%x dir %s if_index %u",
			allow?"allowed":"dropped", can_ev->can_event.can_header.msg_id,
			(can_ev->dir == DIR_IN)?"in":"out",
			can_ev->can_event.can_header.if_index);
}

static void generate_ip_log_extention(char *dst, int len, bool allow, ip_event_t *ip_ev)
{
	snprintf(dst, len, "ip %s: src %d.%d.%d.%d sport %d dst %d.%d.%d.%d dport %d proto %d",
			allow?"allowed":"dropped",
			(ip_ev->saddr.v4addr & 0xFF000000)>>24,
			(ip_ev->saddr.v4addr & 0xFF0000)>>16,
			(ip_ev->saddr.v4addr & 0xFF00)>>8,
			(ip_ev->saddr.v4addr & 0xFF),
			ip_ev->sport,
			(ip_ev->daddr.v4addr & 0xFF000000)>>24,
			(ip_ev->daddr.v4addr & 0xFF0000)>>16,
			(ip_ev->daddr.v4addr & 0xFF00)>>8,
			(ip_ev->daddr.v4addr & 0xFF),
			ip_ev->dport, ip_ev->ip_proto);
}

static void generate_file_log_extention(char *dst, int len, bool allow, vsentry_event_t *file_ev)
{
	snprintf(dst, len, "file %s: inode %lu",
			allow?"allowed":"dropped",
			file_ev->file_event.file_ino);
}

static void genl_log_print_cef_msg(vsentry_event_t *event)
{
	unsigned char cef_buffer[PAD_SIZE];

	switch(event->type) {
	case CLS_IP_RULE_TYPE:
		generate_ip_log_extention(cef_buffer, PAD_SIZE,
				(event->act_bitmap & VSENTRY_ACTION_ALLOW), &event->ip_event);
		break;
	case CLS_CAN_RULE_TYPE:
		generate_can_log_extention(cef_buffer, PAD_SIZE,
				(event->act_bitmap & VSENTRY_ACTION_ALLOW), event);
		break;
	case CLS_FILE_RULE_TYPE:
		generate_file_log_extention(cef_buffer, PAD_SIZE,
				(event->act_bitmap & VSENTRY_ACTION_ALLOW), event);
		break;
	default:
		return;
	}

	fprintf(stdout, "event log %llu: %s\n", event->ts, cef_buffer);
}

static int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
        memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
        while (RTA_OK(rta, len)) {
                if (rta->rta_type <= max)
                        tb[rta->rta_type] = rta;
                rta = RTA_NEXT(rta,len);
        }

        if (len)
                fprintf(stderr, "deficit %d, rta_len=%d\n", len, rta->rta_len);

        return 0;
}

static void format_netlink(struct nlmsghdr *msg)
{
	struct rtattr *tb[VSENTRY_GENL_ATTR_MAX + 1];
	struct genlmsghdr *ghdr = NLMSG_DATA(msg);
	int len;
	struct rtattr *attrs;

	len = msg->nlmsg_len;

	/* if this message doesn't have the proper family ID, drop it */
	if (msg->nlmsg_type != genl_info.family) {
		fprintf(stderr,"netlink: message received with wrong family id.\n");
		return;
	}

	len -= NLMSG_LENGTH(GENL_HDRLEN);
	if (len < 0) {
		fprintf(stderr, "netlink: wrong controller message len: %d\n", len);
		return;
	}

	attrs = (struct rtattr *)((char *)ghdr + GENL_HDRLEN);
	/* parse the attributes in this message */
	parse_rtattr(tb, VSENTRY_GENL_ATTR_MAX, attrs, len);

	/* if there's an ACPI event attribute... */
	if (tb[VSENTRY_GENL_ATTR_EVENT]) {
		genl_log_print_cef_msg((vsentry_event_t*)RTA_DATA(tb[VSENTRY_GENL_ATTR_EVENT]));
	}
}

static void process_netlink(int fd)
{
	int status;
	struct nlmsghdr *h;
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char buf[8192];

	/* set up the netlink address */
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	status = recvmsg(fd, &msg, 0);
	if (status < 0) {
		if (errno == EINTR)
			return;

		fprintf(stderr, "netlink recvmsg error: %s (%d)\n", strerror(errno), errno);
		return;
	}

	if (status == 0) {
		fprintf(stderr, "netlink connection closed\n");
		return;
	}

	if (msg.msg_namelen != sizeof(nladdr)) {
		fprintf(stderr, "netlink: unexpected address length: %d\n", msg.msg_namelen);
		return;
	}

	/* for each message received */
	for (h = (struct nlmsghdr*)buf; (unsigned)status >= sizeof(*h); ) {
		int len = h->nlmsg_len;
		int l = len - sizeof(*h);

		if (l < 0  ||  len > status) {
			if (msg.msg_flags & MSG_TRUNC) {
				fprintf(stderr, "netlink: message truncated(1)\n");
				return;
			}
			fprintf(stderr, "netlink: malformed message. len: %d\n", len);
			return;
		}

		/* format the message */
		format_netlink(h);

		status -= NLMSG_ALIGN(len);
		h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
	}

	if (msg.msg_flags & MSG_TRUNC) {
		fprintf(stderr, "netlink: message truncated (2)\n");
		return;
	}

	if (status) {
		fprintf(stderr, "netlink: remnant of size %d\n", status);
		return;
	}

	return;
}

static void* vsentry_genl_logger(void *func)
{
	int ret, genetlink_fd;
	struct sockaddr_nl addr;
	int sndbuf = 131072;
	int rcvbuf = 131072;

	memset(&genl_info, 0, sizeof(genl_info));

	ret = ioctl(drv_fd, VSENTRY_IOCTL_GET_GENL_INFO, &genl_info);
	if (ret != 0) {
		fprintf(stderr, "failed to get genl_info: %s (%d)\n", strerror(errno), errno);
		return NULL;
	}

	if (!genl_info.family) {
		fprintf(stderr, "kernel netlink logger family is wrong\n");
		return NULL;
	}

	/* open a socket to the kernel netlink module */
	genetlink_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (genetlink_fd < 0) {
		fprintf(stderr, "failed to open netlink socket: %s (%d)\n", strerror(errno), errno);
		return NULL;
	}

	if (setsockopt(genetlink_fd, SOL_SOCKET,SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
		fprintf(stderr, "setsockopt SO_SNDBUF: %s (%d)\n", strerror(errno), errno);
		return NULL;
	}

	if (setsockopt(genetlink_fd, SOL_SOCKET,SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
		fprintf(stderr, "setsockopt SO_RCVBUF: %s (%d)\n", strerror(errno), errno);
		return NULL;
	}

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = genl_info.mcgrp ? (1 << (genl_info.mcgrp - 1)) : 0;

	if (bind(genetlink_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		fprintf(stderr, "failed to bind netlink socket: %s (%d)\n", strerror(errno), errno);
		return NULL;
	}

	while (1) {
		fd_set rfds;

		FD_ZERO(&rfds);
		FD_SET(genetlink_fd, &rfds);

		ret = select((genetlink_fd + 1), &rfds, NULL, NULL, NULL);
		if (ret > 0) {
			if (FD_ISSET(genetlink_fd , &rfds))
				process_netlink(genetlink_fd);
		}
	}

	return NULL;
}

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
	pthread_t thread;

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

	/* start thread listening for logs over netlink */
	if (pthread_create(&thread, NULL, vsentry_genl_logger, NULL) != 0) {
		fprintf(stderr, "failed to create genl_logger: %s (%d)\n", strerror(errno), errno);
		return VSENTRY_ERROR;
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

