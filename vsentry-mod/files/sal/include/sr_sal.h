#ifndef SR_SAL_H
#define SR_SAL_H

#ifdef PLATFORM_LINUX
#include "sal_linux.h"
#endif /* PLATFORM_LINUX */

/* socket functions */
enum SR_SOCKET_TYPE {
    SOCKET_TCP,
    SOCKET_UDP,
    SOCKET_RAW		
};

int sal_socket(enum SR_SOCKET_TYPE type, int protocol);

#endif /* SR_SAL_H*/
