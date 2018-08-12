#ifndef __SR_CAN_COLLECTOR__
#define __SR_CAN_COLLECTOR__

#include "sr_types.h"
#include "sr_tasks.h"
#include "sr_sal_common.h"
#include "sr_config_parse.h"

#define CAN_COLLECTOR_DISK "/"
#define ANYDEV "any"  /* name of interface to receive from any CAN interface */
#define MAX_INF_NAMES 10 /*the amount of possible different can interface names */
#define INF_NAME_LEN 32 

struct canTaskParams {
    SR_8 can_interface[CAN_NAME];		/* can interface name */
    SR_32 can_fd;				/* fd of the opened socket */
    SR_BOOL can_print;			/* DEBUG: when true prints the candump to stdout */
};

struct candump_log
{
    FILE* log_fp;
    //SR_BOOL uploaded; //if file is uploaded
    //SR_BOOL ready; //if file is max size
};

SR_32 init_can_socket(void);

void log_it(char* str);

SR_32 can_collector_task(void *data);

SR_32 can_collector_init(void *data);

struct canTaskParams *sr_can_collector_args(void);

#endif /* __SR_CAN_COLLECTOR__ */
