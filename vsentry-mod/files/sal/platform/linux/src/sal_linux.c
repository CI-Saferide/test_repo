/* file: sal_linux.c
 * purpose: this file implements the sal functions for linux os
*/

#include "sr_sal.h"

#ifdef PLATFORM_LINUX

#include "sr_netlink.h"


int sal_socket(enum SR_SOCKET_TYPE type, int protocol)
{
	int socket_type;
	
	switch (type) {
		case SOCKET_TCP: socket_type = SOCK_STREAM; break;
		case SOCKET_UDP: socket_type = SOCK_DGRAM; break;
		case SOCKET_RAW: socket_type = SOCK_RAW; break;
	};	
	//return (socket(PF_NETLINK, socket_type, protocol));
	return 0;	
}


#endif /* #ifdef PLATFORM_LINUX */
