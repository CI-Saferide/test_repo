#ifndef SR_LSM_HOOKS_H
#define SR_LSM_HOOKS_H

#include <linux/version.h>
#include <linux/utsname.h>   // for the utsname() release feature
#include <linux/kd.h>
#include <linux/tracehook.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/tty.h>
#include <linux/uaccess.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>	/* for network interface checks */
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/dccp.h>
#include <linux/quota.h>
#include <linux/un.h>		/* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/posix-timers.h>
#include <linux/syslog.h>
#include <linux/user_namespace.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h> 
#include <net/af_unix.h>	/* for Unix socket types */
#include <net/ipv6.h>
#include <net/netlink.h>
#include <net/icmp.h>
#include <net/ip.h>		/* for local_port_range[] */
#include <net/tcp.h>		/* struct or_callable used in sock_rcv_skb */
#include <net/net_namespace.h>
#include <net/netlabel.h>
#include <asm/ioctls.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
#include <linux/lsm_hooks.h>
#include <linux/inet.h>
#include <linux/lsm_audit.h>
#include <linux/export.h>
#include <linux/msg.h>
#include <linux/shm.h>
#include <linux/xfrm.h>
#include <net/inet_connection_sock.h>
#include <net/xfrm.h>
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0) */

int register_lsm_hooks (void);
int unregister_lsm_hooks (void);

/* Supported address families. */
#define SR_AF_UNSPEC	0
#define SR_AF_UNIX		1	/* Unix domain sockets 		*/
#define SR_AF_LOCAL		1	/* POSIX name for AF_UNIX	*/
#define SR_AF_INET		2	/* Internet IP Protocol 	*/
#define SR_AF_AX25		3	/* Amateur Radio AX.25 		*/
#define SR_AF_IPX		4	/* Novell IPX 			*/
#define SR_AF_APPLETALK	5	/* AppleTalk DDP 		*/
#define SR_AF_NETROM	6	/* Amateur Radio NET/ROM 	*/
#define SR_AF_BRIDGE	7	/* Multiprotocol bridge 	*/
#define SR_AF_ATMPVC	8	/* ATM PVCs			*/
#define SR_AF_X25		9	/* Reserved for X.25 project 	*/
#define SR_AF_INET6		10	/* IP version 6			*/
#define SR_AF_ROSE		11	/* Amateur Radio X.25 PLP	*/
#define SR_AF_DECnet	12	/* Reserved for DECnet project	*/
#define SR_AF_NETBEUI	13	/* Reserved for 802.2LLC project*/
#define SR_AF_SECURITY	14	/* Security callback pseudo AF */
#define SR_AF_KEY		15      /* PF_KEY key management API */
#define SR_AF_NETLINK	16
#define SR_AF_ROUTE		SR_AF_NETLINK /* Alias to emulate 4.4BSD */
#define SR_AF_PACKET	17	/* Packet family		*/
#define SR_AF_ASH		18	/* Ash				*/
#define SR_AF_ECONET	19	/* Acorn Econet			*/
#define SR_AF_ATMSVC	20	/* ATM SVCs			*/
#define SR_AF_RDS		21	/* RDS sockets 			*/
#define SR_AF_SNA		22	/* Linux SNA Project (nutters!) */
#define SR_AF_IRDA		23	/* IRDA sockets			*/
#define SR_AF_PPPOX		24	/* PPPoX sockets		*/
#define SR_AF_WANPIPE	25	/* Wanpipe API Sockets */
#define SR_AF_LLC		26	/* Linux LLC			*/
#define SR_AF_IB		27	/* Native InfiniBand address	*/
#define SR_AF_MPLS		28	/* MPLS */
#define SR_AF_CAN		29	/* Controller Area Network      */
#define SR_AF_TIPC		30	/* TIPC sockets			*/
#define SR_AF_BLUETOOTH	31	/* Bluetooth sockets 		*/
#define SR_AF_IUCV		32	/* IUCV sockets			*/
#define SR_AF_RXRPC		33	/* RxRPC sockets 		*/
#define SR_AF_ISDN		34	/* mISDN sockets 		*/
#define SR_AF_PHONET	35	/* Phonet sockets		*/
#define SR_AF_IEEE802154	36	/* IEEE802154 sockets		*/
#define SR_AF_CAIF		37	/* CAIF sockets			*/
#define SR_AF_ALG		38	/* Algorithm sockets		*/
#define SR_AF_NFC		39	/* NFC sockets			*/
#define SR_AF_VSOCK		40	/* vSockets			*/
#define SR_AF_KCM		41	/* Kernel Connection Multiplexor*/
#define SR_AF_QIPCRTR	42	/* Qualcomm IPC Router          */
#define SR_AF_SMC		43	/* smc sockets: reserve number for
								* PF_SMC protocol family that
								* reuses AF_INET address family
								*/
#define SR_AF_MAX		44	/* For now.. */
							
#endif /* SR_LSM_HOOKS_H */
