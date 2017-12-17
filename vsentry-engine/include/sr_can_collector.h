#ifndef __SR_CAN_COLLECTOR__
#define __SR_CAN_COLLECTOR__

#include "sr_types.h"
#include "sr_tasks.h"
#include "sr_sal_common.h"

struct canTaskParams {
    SR_8 *can_interface;		/* can interface name */
    SR_32 can_fd;				/* fd of the opened socket */
    SR_BOOL can_print;			/* DEBUG: when true prints the candump to stdout */
};


struct candump_log
{
    FILE* log_fp;
    //SR_BOOL uploaded; //if file is uploaded
    //SR_BOOL ready; //if file is max size
};

SR_32 init_can_socket(SR_8 *interface);

void log_it(char* str);

SR_32 can_collector_task(void *data);

SR_32 can_collector_init(void *data);

#endif /* __SR_CAN_COLLECTOR__ */
