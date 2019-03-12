#include "classifier.h"
#include "prog_cls.h"
#include "uid_cls.h"
#include "can_cls.h"
#include "net_cls.h"
#include "port_cls.h"
#include "ip_proto_cls.h"
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
static bool file_modified = false;

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
	int ret, drv_fd, genetlink_fd;
	struct sockaddr_nl addr;
	int sndbuf = 131072;
	int rcvbuf = 131072;

	memset(&genl_info, 0, sizeof(genl_info));

	/* config file is ready, lets update the kernel */
	drv_fd = open(BIN_CLS_DRV, O_RDWR|O_SYNC);
	if (drv_fd < 0) {
		fprintf(stderr, "failed to open %s: %s (%d)\n", BIN_CLS_DRV, strerror(errno), errno);
		return NULL;
	}

	ret = ioctl(drv_fd, VSENTRY_IOCTL_GET_GENL_INFO, &genl_info);
	close(drv_fd);
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

static int init_db_file(char *dbfile)
{
	unsigned char pad[PAD_SIZE];
	int size = SHMEM_BUFFER_SIZE;

	db_file = fopen(dbfile, "w+");
	if (!db_file) {
		fprintf(stderr, "failed to create db file %s: %s (%d)\n",
				dbfile, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	memset(pad, 0, PAD_SIZE);

	while (size) {
		fwrite(pad, 1, PAD_SIZE, db_file);
		size -= PAD_SIZE;
	}

	fclose(db_file);

	return VSENTRY_SUCCESS;
}

/* this functio will map the dbfile to this process memory */
static int init_db_mem(char *dbfile)
{
	struct stat st;
	int fd;

	/* open (may create) the db file */
	if (init_db_file(dbfile) != VSENTRY_SUCCESS) {
		fprintf(stderr, "failed to init db file %s\n", dbfile);
		return VSENTRY_ERROR;
	}

	db_file = fopen(dbfile, "r+");
	if (!db_file) {
		fprintf(stderr, "failed to open db file %s: %s (%d)\n",
				dbfile, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	fseek(db_file, 0L, SEEK_SET);

	fd = fileno(db_file);
	if (fd <= 0) {
		fprintf(stderr, "failed to extract dbfile fd %s: %s (%d)\n",
				dbfile, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	if (stat(dbfile, &st)) {
		fprintf(stderr, "failed to stat dbfile fd %s: %s (%d)\n",
				dbfile, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	/* map file to memory */
	/* MAP_LOCKED is marked as it result an error when mapping large files */
	dbmem = mmap(NULL, st.st_size, (PROT_READ | PROT_WRITE),
		(MAP_SHARED/*| MAP_LOCKED*/ ) ,fd, 0);
	if (dbmem == MAP_FAILED) {
		fprintf(stderr, "failed to mmap dbfile fd: %s (%d)\n", strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	dbmem_size = st.st_size;

	return VSENTRY_SUCCESS;
}

int bin_cls_init(void)
{
	act_t act;
	unsigned int mode = CLS_MODE_ENFROCE;
	struct config_params_t *config = sr_config_get_param();
	pthread_t thread;

	/* start thread listening for logs over netlink */
	if (pthread_create(&thread, NULL, vsentry_genl_logger, NULL) != 0)
		fprintf(stderr, "failed to create genl_logger: %s (%d)\n", strerror(errno), errno);

	if (init_db_mem(DB_FILE_TMP) != VSENTRY_SUCCESS)
		return SR_ERROR;

	cls_handle_event(VSENTRY_REGISTER_PRINTF, (void*)printf, false);

	/* init classifier database used by vsentry-eng */
	if (cls_handle_event(VSENTRY_CLASIFFIER_INIT, dbmem, false) != VSENTRY_SUCCESS) {
		fprintf(stderr, "failed to init standalone classifier\n");
		goto exit_err;
	}

	act.action_bitmap = 0;
	if (config->default_can_action & SR_CLS_ACTION_ALLOW)
		act.action_bitmap = VSENTRY_ACTION_ALLOW;

	if (config->default_can_action & SR_CLS_ACTION_LOG)
		act.action_bitmap = VSENTRY_ACTION_LOG;

	cls_default_action(CLS_CAN_RULE_TYPE, &act);

	act.action_bitmap = 0;
	if (config->default_net_action & SR_CLS_ACTION_ALLOW)
		act.action_bitmap = VSENTRY_ACTION_ALLOW;

	if (config->default_net_action & SR_CLS_ACTION_LOG)
		act.action_bitmap = VSENTRY_ACTION_LOG;

	cls_default_action(CLS_IP_RULE_TYPE, &act);

	cls_handle_event(VSENTRY_CLASIFFIER_SET_MODE, (vsentry_event_t*)&mode, false);

	return SR_SUCCESS;

exit_err:
	if (db_file) {
		fsync(fileno(db_file));
		fclose(db_file);
	}

	if (dbmem)
		munmap(dbmem, dbmem_size);

	return SR_ERROR;
}

int bin_cls_reload(void)
{
	int ret, drv_fd;

	drv_fd = open(BIN_CLS_DRV, O_RDWR|O_SYNC);
	if (drv_fd < 0) {
		fprintf(stderr, "failed to open %s: %s (%d)\n", BIN_CLS_DRV, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	ret = ioctl(drv_fd, VSENTRY_IOCTL_UPDATE_EXECFILE, CLS_FILE);
	if (ret != 0)
		fprintf(stderr, "failed to update execfile %s: %s (%d)\n", CLS_FILE, strerror(errno), errno);

	close(drv_fd);

	if (ret)
		return SR_ERROR;

	return SR_SUCCESS;
}

int bin_cls_update(bool force)
{
	FILE *update_db_file = NULL;
	int ret, drv_fd = 0;

	if (!dbmem || !db_file)
		return SR_ERROR;

	if(!force && !file_modified) {
		fprintf(stdout, "skip, DB was not modified\n");
		return SR_SUCCESS;
	}

	/* copy the current configuration to the actual config file */
	fsync(fileno(db_file));

	update_db_file = fopen(DB_FILE, "w+");
	if (!update_db_file) {
		fprintf(stderr, "failed to open %s: %s (%d)\n", DB_FILE, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	ret = write(fileno(update_db_file), dbmem, dbmem_size);
	if (ret != dbmem_size) {
		fprintf(stderr, "failed to copy from %s to %s: %s (%d)\n",
				DB_FILE_TMP, DB_FILE, strerror(errno), errno);
		fclose(update_db_file);
		return VSENTRY_ERROR;
	}

	fclose(update_db_file);

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

	file_modified = false;

	if (ret)
		return SR_ERROR;

	return SR_SUCCESS;
}

int bin_cls_toggle_enable(void)
{
	int ret, drv_fd;
	struct vsentry_state state;
	unsigned int vs_enable;

	drv_fd = open(BIN_CLS_DRV, O_RDWR|O_SYNC);
	if (drv_fd < 0) {
		fprintf(stderr, "failed to open %s: %s (%d)\n", BIN_CLS_DRV, strerror(errno), errno);
		return VSENTRY_ERROR;
	}

	ret = ioctl(drv_fd, VSENTRY_IOCTL_GET_STATE, &state);
	if (ret != 0) {
		fprintf(stderr, "failed to ioctl %s: %s (%d)\n", BIN_CLS_DRV, strerror(errno), errno);
		goto toggle_exit;
	}

	if (state.enabled)
		vs_enable = false;
	else
		vs_enable = true;

	ret = ioctl(drv_fd, VSENTRY_IOCTL_SET_ENABLE, &vs_enable);
	if (ret != 0) {
		fprintf(stderr, "failed to %s %s: %s (%d)\n", vs_enable?"enable":"disable",
				BIN_CLS_DRV, strerror(errno), errno);
	}

toggle_exit:
	close(drv_fd);

	if (ret)
		return SR_ERROR;

	return SR_SUCCESS;
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
			if (ret != SR_SUCCESS) {
				fprintf(stderr, "failed to update execfile %s\n", CLS_FILE);
				goto enable_exit;
			}
		}

		if (!state.db_present) {
			ret = bin_cls_update(false);
			if (ret != SR_SUCCESS) {
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
		return SR_ERROR;

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

	file_modified = true;

	if (add)
		ret = cls_add_rule(type, rule, act_name, strlen(act_name), limit);
	else
		ret = cls_del_rule(type, rule);

	if (ret != VSENTRY_SUCCESS)
		return SR_ERROR;

	return SR_SUCCESS;
}

int cls_uid_rule(bool add, unsigned int type, unsigned int rule,
		unsigned int uid)
{
	int ret;

	if (!dbmem)
		return SR_ERROR;

	file_modified = true;

	if (add)
		ret = uid_cls_add_rule(type, rule, uid);
	else
		ret = uid_cls_del_rule(type, rule, uid);

	if (ret != VSENTRY_SUCCESS)
		return SR_ERROR;

	return SR_SUCCESS;
}

int cls_prog_rule(bool add, unsigned int type, unsigned int rule,
		unsigned int exec)
{
	int ret;

	if (!dbmem)
		return SR_ERROR;

	file_modified = true;

	if (!exec)
		exec = PROG_ANY;

	if (add)
		ret = prog_cls_add_rule(type, rule, exec);
	else
		ret = prog_cls_del_rule(type, rule, exec);

	if (ret != VSENTRY_SUCCESS)
		return SR_ERROR;

	return SR_SUCCESS;
}

int cls_can_rule(bool add, unsigned int rule, unsigned int msg_id, unsigned int dir, unsigned int if_index)
{
	int ret;
	can_header_t can_hdr;

	if (!dbmem)
		return SR_ERROR;

	file_modified = true;

	memset(&can_hdr, 0, sizeof(can_header_t));
	can_hdr.msg_id = msg_id;
	can_hdr.if_index = if_index;

	if (add)
		ret = can_cls_add_rule(rule, &can_hdr, dir);
	else
		ret = can_cls_del_rule(rule, &can_hdr, dir);

	if (ret != VSENTRY_SUCCESS)
		return SR_ERROR;

	return SR_SUCCESS;
}

int cls_ip_rule(bool add, unsigned int rule, unsigned int addr, unsigned int netmask, unsigned int dir)
{
	int ret;

	file_modified = true;

	if (add)
		ret = net_cls_add_rule(rule, addr, netmask, dir);
	else
		ret = net_cls_del_rule(rule, addr, netmask, dir);

	if (ret != VSENTRY_SUCCESS)
		return SR_ERROR;

	return SR_SUCCESS;
}

int cls_port_rule(bool add, unsigned int rule, unsigned int port, unsigned int type, unsigned int dir)
{
	int ret;

	if (!port)
		port = PORT_ANY;

	file_modified = true;

	if (add)
		ret = port_cls_add_rule(rule, port, type, dir);
	else
		ret = port_cls_del_rule(rule, port, type, dir);

	if (ret != VSENTRY_SUCCESS)
		return SR_ERROR;

	return SR_SUCCESS;
}

int cls_ip_porto_rule(bool add, unsigned int rule, unsigned int ip_porto)
{
	int ret;

	file_modified = true;

	if (add)
		ret = ip_proto_cls_add_rule(rule, ip_porto);
	else
		ret = ip_proto_cls_del_rule(rule, ip_porto);

	if (ret != VSENTRY_SUCCESS)
		return SR_ERROR;

	return SR_SUCCESS;
}

void cls_print(void)
{
	int drv_fd;

	cls_print_db();

	drv_fd = open(BIN_CLS_DRV, O_RDWR|O_SYNC);
	if (drv_fd < 0) {
		fprintf(stderr, "failed to open %s: %s (%d)\n", BIN_CLS_DRV, strerror(errno), errno);
		return;
	}

	ioctl(drv_fd, VSENTRY_IOCTL_PRINT_INFO, NULL);

	close(drv_fd);
}
