#ifndef _EVENT_MEDIATOR_H
#define _EVENT_MEDIATOR_H

/* Supported address families */
#define SR_AF_UNSPEC		0
#define SR_AF_UNIX			1	/* Unix domain sockets 		*/
#define SR_AF_LOCAL			1	/* POSIX name for AF_UNIX	*/
#define SR_AF_INET			2	/* Internet IP Protocol 	*/
#define SR_AF_AX25			3	/* Amateur Radio AX.25 		*/
#define SR_AF_IPX			4	/* Novell IPX 			*/
#define SR_AF_APPLETALK		5	/* AppleTalk DDP 		*/
#define SR_AF_NETROM		6	/* Amateur Radio NET/ROM 	*/
#define SR_AF_BRIDGE		7	/* Multiprotocol bridge 	*/
#define SR_AF_ATMPVC		8	/* ATM PVCs			*/
#define SR_AF_X25			9	/* Reserved for X.25 project 	*/
#define SR_AF_INET6			10	/* IP version 6			*/
#define SR_AF_ROSE			11	/* Amateur Radio X.25 PLP	*/
#define SR_AF_DECnet		12	/* Reserved for DECnet project	*/
#define SR_AF_NETBEUI		13	/* Reserved for 802.2LLC project*/
#define SR_AF_SECURITY		14	/* Security callback pseudo AF */
#define SR_AF_KEY			15      /* PF_KEY key management API */
#define SR_AF_NETLINK		16
#define SR_AF_ROUTE			SR_AF_NETLINK /* Alias to emulate 4.4BSD */
#define SR_AF_PACKET		17	/* Packet family		*/
#define SR_AF_ASH			18	/* Ash				*/
#define SR_AF_ECONET		19	/* Acorn Econet			*/
#define SR_AF_ATMSVC		20	/* ATM SVCs			*/
#define SR_AF_RDS			21	/* RDS sockets 			*/
#define SR_AF_SNA			22	/* Linux SNA Project (nutters!) */
#define SR_AF_IRDA			23	/* IRDA sockets			*/
#define SR_AF_PPPOX			24	/* PPPoX sockets		*/
#define SR_AF_WANPIPE		25	/* Wanpipe API Sockets */
#define SR_AF_LLC			26	/* Linux LLC			*/
#define SR_AF_IB			27	/* Native InfiniBand address	*/
#define SR_AF_MPLS			28	/* MPLS */
#define SR_AF_CAN			29	/* Controller Area Network      */
#define SR_AF_TIPC			30	/* TIPC sockets			*/
#define SR_AF_BLUETOOTH		31	/* Bluetooth sockets 		*/
#define SR_AF_IUCV			32	/* IUCV sockets			*/
#define SR_AF_RXRPC			33	/* RxRPC sockets 		*/
#define SR_AF_ISDN			34	/* mISDN sockets 		*/
#define SR_AF_PHONET		35	/* Phonet sockets		*/
#define SR_AF_IEEE802154	36	/* IEEE802154 sockets		*/
#define SR_AF_CAIF			37	/* CAIF sockets			*/
#define SR_AF_ALG			38	/* Algorithm sockets		*/
#define SR_AF_NFC			39	/* NFC sockets			*/
#define SR_AF_VSOCK			40	/* vSockets			*/
#define SR_AF_KCM			41	/* Kernel Connection Multiplexor*/
#define SR_AF_QIPCRTR		42	/* Qualcomm IPC Router          */
#define SR_AF_SMC			43	/* smc sockets: reserve number for
								* PF_SMC protocol family that
								* reuses AF_INET address family
								*/
#define SR_AF_MAX			44	/* For now.. */

SR_32 vsentry_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mask);
SR_32 vsentry_inode_unlink(struct inode *dir, struct dentry *dentry);
SR_32 vsentry_inode_symlink(struct inode *dir, struct dentry *dentry, const SR_8 *name);
SR_32 vsentry_inode_rmdir(struct inode *dir, struct dentry *dentry);
SR_32 vsentry_socket_connect(struct socket *sock, struct sockaddr *address, SR_32 addrlen);
SR_32 vsentry_path_chmod(struct path *path, umode_t mode);
SR_32 vsentry_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode);
SR_32 vsentry_file_open(struct file *file, const struct cred *cred);
SR_32 vsentry_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry);
SR_32 vsentry_socket_create(SR_32 family, SR_32 type, SR_32 protocol, SR_32 kern);
SR_32 vsentry_incoming_connection(struct sk_buff *skb);
SR_32 vsentry_socket_sendmsg(struct socket *sock,struct msghdr *msg, SR_32 size);
SR_32 vsentry_bprm_check_security(struct linux_binprm *bprm);
void vsentry_task_free(struct task_struct *task);
#endif /* _EVENT_MEDIATOR_H */
