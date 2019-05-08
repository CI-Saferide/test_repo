#include "classifier.h"
#include "prog_cls.h"
#include "uid_cls.h"
#include "can_cls.h"
#include "net_cls.h"
#include "port_cls.h"
#include "ip_proto_cls.h"
#include "file_cls.h"
#include "sr_sal_common.h"
#include "sr_log.h"
#include "sr_ver.h"
#include "sr_bin_cls_eng.h"
#include "sr_config_parse.h"
#include <linux/vsentry/vsentry.h>
#include <linux/vsentry/vsentry_drv.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>

#define PAD_SIZE 		4096

static void *dbmem = NULL;
static int dbmem_size = 0;
static FILE *db_file = NULL;
static struct vsentry_genl_info genl_info;
/* file_modified will signal if we need to download the DB file
 * set tot true if modified.*/
static bool file_modified = false;

static char *db_file_name = DB_FILE;
static char *cls_file_name = CLS_FILE;

static int drv_fd = 0;

static void generate_can_log_extention(char *dst, int len, bool allow, vsentry_event_t *can_ev)
{
	snprintf(dst, len, "msg=can message %s: msgid 0x%x dir %s if_index %u",
			allow?"allowed":"dropped", can_ev->can_event.can_header.msg_id,
					(can_ev->dir == DIR_IN)?"in":"out",
					can_ev->can_event.can_header.if_index);
}

static void generate_ip_log_extention(char *dst, int len, bool allow, ip_event_t *ip_ev)
{
	snprintf(dst, len, "msg=ip message %s: src %d.%d.%d.%d sport %d dst %d.%d.%d.%d dport %d proto %d\n",
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

static void genl_log_print_cef_msg(vsentry_event_t *event)
{
	SR_8 cef_buffer[MAX_PAYLOAD];
	time_t timer;
	SR_8 buffer[26];
	SR_8 buffer_tz[8];
	struct tm* tm_info;
	struct config_params_t *config_params;
	enum SR_CEF_CLASS_ID class;
	enum SR_CEF_SEVERITY sev;
	char extension[MAX_PAYLOAD];
	char *name;

	if (event->act_bitmap & VSENTRY_ACTION_ALLOW) {
		sev = SEVERITY_LOW;
		name = "info";
	} else {
		sev = SEVERITY_HIGH;
		name = "error";
	}

	switch(event->type) {
	case CLS_IP_RULE_TYPE:
		generate_ip_log_extention(extension, MAX_PAYLOAD,
				(event->act_bitmap & VSENTRY_ACTION_ALLOW), &event->ip_event);
		class = SR_CEF_CID_NETWORK;
		break;
	case CLS_CAN_RULE_TYPE:
		generate_can_log_extention(extension, MAX_PAYLOAD,
				(event->act_bitmap & VSENTRY_ACTION_ALLOW), event);
		class = SR_CEF_CID_CAN;
		break;
	case CLS_FILE_RULE_TYPE:
		generate_can_log_extention(extension, MAX_PAYLOAD,
				(event->act_bitmap & VSENTRY_ACTION_ALLOW), event);
		class = SR_CEF_CID_FILE;
		break;
	default:
		return;
	}

	config_params = sr_config_get_param();

	time(&timer);
	timer = event->ts/1000000;
	tm_info = localtime(&timer);
	strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
	strftime(buffer_tz,sizeof(buffer_tz), "%z", tm_info);

	snprintf(cef_buffer,MAX_PAYLOAD, "CEF:%d|%s|%s|%d.%d|%d|%s|%d|%s=%s.%.3llu%s %s=%s %s=%s %s\n",
			CEF_VER, VENDOR_NAME, PRODUCT_NAME, VSENTRY_VER_MAJOR,
			VSENTRY_VER_MINOR, class, name, sev,
			DEVIC_RECEIPT_TIME, buffer, (event->ts%1000000/1000), buffer_tz,
			DEVICE_EXTERNAL_ID, config_params->vin,
			DEVICE_FACILITY, LOG_FROM_KERNEL,
			extension);

	handle_log_options(cef_buffer, sev);
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

static int drv_init(void)
{
	drv_fd = open(BIN_CLS_DRV, O_RDWR|O_SYNC);
	if (drv_fd < 0) {
		fprintf(stderr, "failed to open %s: %s (%d)\n", BIN_CLS_DRV, strerror(errno), errno);
		drv_fd = 0;
		return VSENTRY_ERROR;
	}

	return VSENTRY_SUCCESS;
}

static int drv_get_state(struct vsentry_state *state)
{
	if (drv_fd < 0)
		return VSENTRY_ERROR;

	if (ioctl(drv_fd, VSENTRY_IOCTL_GET_STATE, state) != 0) {
		fprintf(stderr, "failed to ioctl %s: %s (%d)\n", BIN_CLS_DRV, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	return VSENTRY_SUCCESS;
}

int bin_cls_print_state(void)
{
	struct vsentry_state state;

	if (ioctl(drv_fd, VSENTRY_IOCTL_GET_STATE, &state) != 0) {
		fprintf(stderr, "failed to ioctl %s: %s (%d)\n", BIN_CLS_DRV, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	fprintf(stdout, "classifier is %s\n", state.enabled?"enabled":"disabled");
	switch (state.mode) {
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

	switch (state.file_cls_mode) {
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

	fprintf(stdout, "classifier binary is %s present\n", state.cls_present?"":"not");
	fprintf(stdout, "classifier database is %s present\n", state.cls_present?"":"not");

	return VSENTRY_SUCCESS;
}

static int drv_set_enable(bool enable)
{
	unsigned int vs_enable = enable;

	if (drv_fd < 0)
		return VSENTRY_ERROR;

	if (ioctl(drv_fd, VSENTRY_IOCTL_SET_ENABLE, &vs_enable) != 0) {
		fprintf(stderr, "failed to %s %s: %s (%d)\n", vs_enable?"enable":"disable",
				BIN_CLS_DRV, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	fprintf(stderr, "vsentry cls bin is %s\n", vs_enable?"enabled":"disabled");

	return VSENTRY_SUCCESS;
}

static int drv_set_mode(unsigned int mode)
{
	unsigned int vs_mode = mode;
	struct vsentry_state state;

	if (drv_get_state(&state) != VSENTRY_SUCCESS)
		return SR_ERROR;

	if (state.mode == vs_mode)
		return VSENTRY_SUCCESS;

	if (ioctl(drv_fd, VSENTRY_IOCTL_SET_MODE, &vs_mode) != 0) {
		fprintf(stderr, "failed to set mode %d %s: %s (%d)\n", vs_mode, BIN_CLS_DRV, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	switch (vs_mode) {
	case VSENTRY_MODE_ENFORCE:
		fprintf(stdout, "vsentry cls bin set to enforce mode\n");
		break;
	case VSENTRY_MODE_PERMISSIVE:
		fprintf(stdout, "vsentry cls bin set to permissive mode\n");
		break;
#ifdef ENABLE_LEARN
	case VSENTRY_MODE_LEARN:
		fprintf(stdout, "vsentry cls bin set to learn mode\n");
		break;
#endif
	default:
		fprintf(stderr, "invalid mode\n");
		return VSENTRY_ERROR;
	}

	return VSENTRY_SUCCESS;
}

static int bin_cls_set_cls_file_mode(unsigned int file_cls_mode)
{
	unsigned int vs_file_cls_mode = file_cls_mode;
	struct vsentry_state state;

	if (drv_get_state(&state) != VSENTRY_SUCCESS)
		return SR_ERROR;

	if (state.file_cls_mode == vs_file_cls_mode)
		return VSENTRY_SUCCESS;

	if (ioctl(drv_fd, VSENTRY_IOCTL_FILE_CLS_MODE, &vs_file_cls_mode) != 0) {
		fprintf(stderr, "failed to set file cls mode %s: %s (%d)\n", BIN_CLS_DRV, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	fprintf(stdout, "set vsentry file cls mode to %s\n", vs_file_cls_mode==FILE_CLS_MODE_INODE?"inode":"string");

	return VSENTRY_SUCCESS;
}

static int init_db_file(char *file_name)
{
	unsigned char pad[PAD_SIZE];
	int size = SHMEM_BUFFER_SIZE;

	db_file = fopen(file_name, "w+");
	if (!db_file) {
		fprintf(stderr, "failed to create db file %s: %s (%d)\n",
				file_name, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	memset(pad, 0, PAD_SIZE);

	while (size) {
		fwrite(pad, 1, PAD_SIZE, db_file);
		size -= PAD_SIZE;
	}

	fprintf(stdout, "created new db file %s\n", file_name);

	return VSENTRY_SUCCESS;
}

/* this function will map the dbfile to this process memory */
static int init_db_mem(void)
{
	struct stat st;
	int fd;

	/* open (may create) the db file */
	db_file = fopen(db_file_name, "r+");
	if (!db_file) {
		if (init_db_file(db_file_name) != VSENTRY_SUCCESS) {
			fprintf(stderr, "failed to init db file %s\n", db_file_name);
			return VSENTRY_ERROR;
		}
	}

	fprintf(stdout, "using db file %s\n", db_file_name);

	fseek(db_file, 0L, SEEK_SET);

	fd = fileno(db_file);
	if (fd <= 0) {
		fprintf(stderr, "failed to extract dbfile fd %s: %s (%d)\n",
				db_file_name, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	if (stat(db_file_name, &st)) {
		fprintf(stderr, "failed to stat dbfile fd %s: %s (%d)\n",
				db_file_name, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	/* map file to memory */
	/* MAP_LOCKED is marked as it result an error when mapping large files */
	dbmem = mmap(NULL, st.st_size, (PROT_READ | PROT_WRITE),
		(MAP_SHARED/*| MAP_LOCKED*/ ) ,fd, 0);
	if (dbmem == MAP_FAILED) {
		fprintf(stderr, "failed to mmap %s fd: %s (%d)\n", db_file_name, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	fprintf(stdout, "database memory %p mmaped successfully size %u (file %s)\n",
			dbmem, (unsigned int)st.st_size, db_file_name);

	dbmem_size = st.st_size;

	return VSENTRY_SUCCESS;
}

//static int copy_db_file(char *dst_file_name)
//{
//	static FILE *dst_file = NULL;
//
//	/* open (may create) the db file */
//	dst_file = fopen(dst_file_name, "w+");
//	if (!db_file) {
//		fprintf(stderr, "failed to open dst_file %s\n", dst_file_name);
//		return VSENTRY_ERROR;
//	}
//
//	if (fwrite(dbmem, dbmem_size, 1, dst_file) != dbmem_size)
//		fprintf(stderr, "could not copy all db to %s\n", dst_file_name);
//
//	fclose(dst_file);
//
//	return VSENTRY_SUCCESS;
//}

static void deinit_db_mem(void)
{
	if (dbmem) {
		munmap(dbmem, dbmem_size);
		dbmem = NULL;
		dbmem_size = 0;
	}

	if (db_file) {
		fsync(fileno(db_file));
		fclose(db_file);
		db_file = NULL;
	}
}

static int bin_cls_db_init(void)
{
	act_t act;
	struct config_params_t *config = sr_config_get_param();

	if (init_db_mem() != VSENTRY_SUCCESS)
		return SR_ERROR;

	/* init classifier database used by vsentry-eng */
	cls_handle_event(VSENTRY_REGISTER_PRINTF, (void*)printf);
	if (cls_handle_event(VSENTRY_CLASIFFIER_INIT, dbmem) != VSENTRY_SUCCESS) {
		fprintf(stderr, "failed to init standalone classifier\n");
		goto exit_err;
	}

	act.action_bitmap = 0;
	if (config->default_can_action & SR_CLS_ACTION_ALLOW)
		act.action_bitmap = VSENTRY_ACTION_ALLOW;

	if (config->default_can_action & SR_CLS_ACTION_LOG)
		act.action_bitmap = VSENTRY_ACTION_LOG;

	cls_default_action(CLS_CAN_RULE_TYPE, &act, 0);

	act.action_bitmap = 0;
	if (config->default_net_action & SR_CLS_ACTION_ALLOW)
		act.action_bitmap = VSENTRY_ACTION_ALLOW;

	if (config->default_net_action & SR_CLS_ACTION_LOG)
		act.action_bitmap = VSENTRY_ACTION_LOG;

	cls_default_action(CLS_IP_RULE_TYPE, &act, 0);

	act.action_bitmap = 0;
	if (config->default_file_action & SR_CLS_ACTION_ALLOW)
		act.action_bitmap = VSENTRY_ACTION_ALLOW;

	if (config->default_file_action & SR_CLS_ACTION_LOG)
		act.action_bitmap = VSENTRY_ACTION_LOG;

	cls_default_action(CLS_FILE_RULE_TYPE, &act, 0);

	file_modified = true;

	fprintf(stdout, "db file %s initialized\n", db_file_name);

	return VSENTRY_SUCCESS;

exit_err:
	if (dbmem)
		munmap(dbmem, dbmem_size);

	if (db_file) {
		fsync(fileno(db_file));
		fclose(db_file);
	}

	return VSENTRY_ERROR;
}

#ifdef ENABLE_LEARN

static int bin_cls_db_upload(void)
{
	struct vsentry_state state;

	/* get the current vsentry state */
	if (drv_get_state(&state) != VSENTRY_SUCCESS)
		return VSENTRY_ERROR;

	/* make sure vsentry is disabled */
	if (state.enabled) {
		if (drv_set_enable(false) != VSENTRY_SUCCESS)
			return VSENTRY_ERROR;
	}

	/* deinit cls db */
	deinit_db_mem();

	/* copy the kenrel DB */
	if (ioctl(drv_fd, VSENTRY_IOCTL_COPY_DBFILE, db_file_name) != 0) {
		fprintf(stderr, "failed to copy kernel db to dbfile %s: %s (%d)\n", db_file_name, strerror(errno), errno);
		unlink(db_file_name);
	}

	/* re-init the db */
	bin_cls_db_init();

	/* re-enable if needed */
	if (state.enabled) {
		if (drv_set_enable(true) != VSENTRY_SUCCESS)
			return VSENTRY_ERROR;
	}

	/* file rules consolidation */
//	file_cls_trim(3, 10);

	return VSENTRY_SUCCESS;
}

int bin_cls_learn(bool learn)
{
	if (learn) {
		/* enable vsentry */
		bin_cls_enable(true);

		/* set the DB into learn mode */
		bin_cls_set_cls_file_mode(FILE_CLS_MODE_STR);
		drv_set_mode(VSENTRY_MODE_LEARN);

		fprintf(stdout, "vsentry binary classifier in learn mode\n");
	} else {
		struct vsentry_state state;

		drv_get_state(&state);

		/* disable vsentry */
		bin_cls_enable(false);

		/* get the current DB from kernel */
		if (bin_cls_db_upload())
			return SR_ERROR;

		bin_cls_update(true);

		/* set the DB to enforce mode */
		drv_set_mode(VSENTRY_MODE_ENFORCE);

		/* enable vsentry */
		if (state.enabled)
			bin_cls_enable(true);

		fprintf(stdout, "vsentry binary classifier in enforce mode\n");
	}

	return SR_SUCCESS;
}

#endif

int bin_cls_init(char *cls, char *db)
{
	pthread_t thread;
	struct vsentry_state state;

	if (cls)
		cls_file_name = cls;

	if (db)
		db_file_name = db;

	/* init (if needed) the db file */
	if (bin_cls_db_init() != VSENTRY_SUCCESS)
		return SR_ERROR;

	/* init the driver i/f */
	if (drv_init() != VSENTRY_SUCCESS)
		return SR_ERROR;

	/* check cls driver state */
	if (drv_get_state(&state) != VSENTRY_SUCCESS)
		return SR_ERROR;

#ifdef ENABLE_LEARN
	if (state.enabled == true &&state.mode == VSENTRY_MODE_LEARN) {
		/* the classifier was booted with empty db and was set to learn mode.
		 * we need to upload the kernel db and use it.
		 * THIS MUST HAPPEN BEFORE RADIS RECONF */
		bin_cls_db_upload();

		cls_set_mode(VSENTRY_MODE_ENFORCE);

		bin_cls_update(true);
	} else {
#endif
		if (!state.cls_present) {
			if (bin_cls_reload() != VSENTRY_SUCCESS)
				return SR_ERROR;
			fprintf(stdout, "binary classifier %s loaded\n", cls_file_name);
		}

		if (!state.db_present) {
			if (bin_cls_update(true) != VSENTRY_SUCCESS)
				return SR_ERROR;
			fprintf(stdout, "db file %s loaded\n", db_file_name);
		}
#ifdef ENABLE_LEARN
	}
#endif

	/* start thread listening for logs over netlink */
	if (pthread_create(&thread, NULL, vsentry_genl_logger, NULL) != 0) {
		fprintf(stderr, "failed to create genl_logger: %s (%d)\n", strerror(errno), errno);
		return SR_ERROR;
	}

	fprintf(stdout, "vsentry binary classifier initialized\n");

	return SR_SUCCESS;
}

void bin_cls_deinit(void)
{
	deinit_db_mem();

	close(drv_fd);
}

int bin_cls_reload(void)
{
	if (drv_fd < 0)
		return VSENTRY_ERROR;

	if (ioctl(drv_fd, VSENTRY_IOCTL_UPDATE_EXECFILE, cls_file_name) != 0) {
		fprintf(stderr, "failed to update execfile %s: %s (%d)\n", cls_file_name,
				strerror(errno), errno);
		return SR_ERROR;
	}

	fprintf(stdout, "vsentry binary classifier reloaded\n");

	return SR_SUCCESS;
}

static unsigned long get_file_inode(char *filename)
{
	struct stat buf = {};


	if(stat(filename, &buf))
		return 0;

	return buf.st_ino;
}

int bin_cls_update(bool force)
{
	if(!force && !file_modified) {
		fprintf(stdout, "skip, DB was not modified\n");
		return SR_SUCCESS;
	}

	/* go over the file rules and update the inodes */
	file_cls_update_tree_inodes(get_file_inode);
	prog_cls_update_tree_inodes(get_file_inode);

	/* at this point we can move to file classification by inode */

	fsync(fileno(db_file));
	
	/* update the kernel DB */
	if (ioctl(drv_fd, VSENTRY_IOCTL_UPDATE_DBFILE, db_file_name) != 0) {
		fprintf(stderr, "failed to update dbfile %s: %s (%d)\n", db_file_name, strerror(errno), errno);
		return SR_ERROR;
	}

	bin_cls_set_cls_file_mode(FILE_CLS_MODE_INODE);

	file_modified = false;

	fprintf(stdout, "vsentry binary classifier updated\n");

	return SR_SUCCESS;
}

int bin_cls_toggle_enable(void)
{
	struct vsentry_state state;

	if (drv_get_state(&state) != VSENTRY_SUCCESS)
		return SR_ERROR;

	if (drv_set_enable(!state.enabled) != VSENTRY_SUCCESS)
		return SR_ERROR;

	return SR_SUCCESS;
}

int bin_cls_enable(bool enable)
{
	struct vsentry_state state;

	if (drv_get_state(&state) != VSENTRY_SUCCESS)
		return SR_ERROR;

	if (enable) {
		if (!state.cls_present) {
			if (bin_cls_reload() != SR_SUCCESS) {
				fprintf(stderr, "failed to update execfile %s\n", cls_file_name);
				return SR_ERROR;
			}
		}

		if (!state.db_present) {
			if (bin_cls_update(false) != SR_SUCCESS) {
				fprintf(stderr, "failed to update dbfile %s\n", db_file_name);
				return SR_ERROR;
			}
		}

		/* set the DB to enforce mode */
		if (state.mode != VSENTRY_MODE_ENFORCE) {
			if (drv_set_mode(VSENTRY_MODE_ENFORCE) != VSENTRY_SUCCESS) {
				fprintf(stderr, "failed to update dbfile %s\n", db_file_name);
				return SR_ERROR;
			}
		}
	}

	if (drv_set_enable(enable) != VSENTRY_SUCCESS)
		return SR_ERROR;

	fprintf(stdout, "vsentry binary classifier is %s\n", enable?"enabled":"disabled");

	return SR_SUCCESS;
}

int cls_action(bool add, bool allow, bool log, char *name)
{
	act_t act;

	if (!dbmem)
		return SR_ERROR;

	file_modified = true;

	if (add) {
		memset(&act, 0, sizeof(act_t));

		act.name_len = snprintf(act.name, ACTION_NAME_SIZE, "%s", name);
		if (allow)
			act.action_bitmap = VSENTRY_ACTION_ALLOW;

		if (log)
			act.action_bitmap |= VSENTRY_ACTION_LOG;

		return action_cls_add(&act);
	}

	return action_cls_del(name, strlen(name));
}

int cls_rule(bool add, unsigned int type, unsigned int rule, char *act_name, unsigned int limit)
{
	int ret;

	if (!dbmem)
		return SR_ERROR;

	if (add)
		ret = cls_add_rule(type, rule, act_name, strlen(act_name), limit);
	else
		ret = cls_del_rule(type, rule);

	if (ret != VSENTRY_SUCCESS)
		return SR_ERROR;

	file_modified = true;

	return SR_SUCCESS;
}

int cls_uid_rule(bool add, unsigned int type, unsigned int rule,
		unsigned int uid)
{
	int ret;

	if (!dbmem)
		return SR_ERROR;

	if (add)
		ret = uid_cls_add_rule(type, rule, uid);
	else
		ret = uid_cls_del_rule(type, rule, uid);

	if (ret != VSENTRY_SUCCESS)
		return SR_ERROR;

	file_modified = true;

	return SR_SUCCESS;
}

int cls_prog_rule(bool add, unsigned int type, unsigned int rule,
		unsigned long exec, char *exec_name)
{
	int ret;

	if (!dbmem)
		return SR_ERROR;

	if (!exec)
		exec = PROG_ANY;

	if (add)
		ret = prog_cls_add_rule(type, rule, exec_name, exec, strlen(exec_name));
	else
		ret = prog_cls_del_rule(type, rule, exec_name);

	if (ret != VSENTRY_SUCCESS)
		return SR_ERROR;

	file_modified = true;

	return SR_SUCCESS;
}

int cls_can_rule(bool add, unsigned int rule, unsigned int msg_id, unsigned int dir, unsigned int if_index)
{
	int ret;
	can_header_t can_hdr;

	if (!dbmem)
		return SR_ERROR;

	memset(&can_hdr, 0, sizeof(can_header_t));
	can_hdr.msg_id = msg_id;
	can_hdr.if_index = if_index;

	if (add)
		ret = can_cls_add_rule(rule, &can_hdr, dir);
	else
		ret = can_cls_del_rule(rule, &can_hdr, dir);

	if (ret != VSENTRY_SUCCESS)
		return SR_ERROR;

	file_modified = true;

	return SR_SUCCESS;
}

int cls_ip_rule(bool add, unsigned int rule, unsigned int addr, unsigned int netmask, unsigned int dir)
{
	int ret;

	if (add)
		ret = net_cls_add_rule(rule, addr, netmask, dir);
	else
		ret = net_cls_del_rule(rule, addr, netmask, dir);

	if (ret != VSENTRY_SUCCESS)
		return SR_ERROR;

	file_modified = true;

	return SR_SUCCESS;
}

int cls_port_rule(bool add, unsigned int rule, unsigned int port, unsigned int type, unsigned int dir)
{
	int ret;

	if (!port)
		port = PORT_ANY;

	if (add)
		ret = port_cls_add_rule(rule, port, type, dir);
	else
		ret = port_cls_del_rule(rule, port, type, dir);

	if (ret != VSENTRY_SUCCESS)
		return SR_ERROR;

	file_modified = true;

	return SR_SUCCESS;
}

int cls_ip_porto_rule(bool add, unsigned int rule, unsigned int ip_porto)
{
	int ret;

	if (add)
		ret = ip_proto_cls_add_rule(rule, ip_porto);
	else
		ret = ip_proto_cls_del_rule(rule, ip_porto);

	if (ret != VSENTRY_SUCCESS)
		return SR_ERROR;

	file_modified = true;

	return SR_SUCCESS;
}

int cls_file_rule(bool add, unsigned int rule, char *filename, unsigned long inode, char *mode)
{
	int ret = 0;
	file_event_t file_ev;

	memset(&file_ev, 0, sizeof(file_event_t));

	file_ev.file_ino = inode;

	if (filename) {
		if (strncmp(filename, "/proc/", 6) == 0)
			file_ev.type = FILE_TYPE_PROCFS;
		else if (strncmp(filename, "/sys/", 5) == 0)
			file_ev.type = FILE_TYPE_SYSFS;
		else {
			file_ev.type = FILE_TYPE_REG;
			file_ev.filename = filename;
			file_ev.filename_len = strlen(filename);
		}
	}

	if (mode) {
		/* in the new classifier we only look on the user bits.
		 * other bit are irrelevant */
		if (strchr(mode, 'r'))
			file_ev.mode |= FILE_MODE_READ;
		if (strchr(mode, 'w'))
			file_ev.mode |= FILE_MODE_WRITE;
		if (strchr(mode, 'x'))
			file_ev.mode |= FILE_MODE_EXEC;
	}

	if (add) {
		if (!file_ev.mode)
			return SR_ERROR;

		ret = file_cls_add_rule(rule, &file_ev);
	} else {
		ret = file_cls_del_rule(rule, &file_ev);
	}

	if (ret != VSENTRY_SUCCESS)
		return SR_ERROR;

	file_modified = true;

	return SR_SUCCESS;
}

void cls_print(void)
{
	cls_print_db();
}
