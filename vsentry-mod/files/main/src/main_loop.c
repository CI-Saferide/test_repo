#include "sal_module.h"
#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_tasks.h"
#include "main_loop.h"
#include "sr_sal_common.h"

#define MAX_RX_MSG_LEN 	512

SR_32 sr_module_loop(void *arg)
{
	sr_shmem* vsshmem;
	SR_32 ret;
	SR_U8 msg[MAX_RX_MSG_LEN];

	sal_printf("module_loop: started ...\n");

	while (!sr_task_should_stop(SR_MODULE_TASK)) {
		/* get the rx buffer ptr */
		vsshmem = sr_msg_get_buf(ENG2MOD_BUF);

		/* if allocated (i.e. engine started ... */
		if (vsshmem && vsshmem->buffer) {
			/* check for incomming msgs from engine */
			while ((ret = sr_read_msg(ENG2MOD_BUF, msg, MAX_RX_MSG_LEN, SR_TRUE)) > 0) {
				/* TODO: read and process data. example: */
				sal_printf("module_loop: read %d bytes\n", ret);
			}

			/* short sleep (2ms) to allow others to run so they 
			   could fill the buffer */;
			sal_schedule_timeout(2*1000);
		} else {
			/* the rx buffer was not alloctaed, goto sleep 
			   and wait for allocation */
			sal_schedule();
		}
	}

	sal_printf("module_loop: ended !!\n");

	return SR_SUCCESS;
}

SR_32 sr_module_start(void)
{
	sal_printf("Starting SR module!\n");

	if (sr_start_task(SR_MODULE_TASK, sr_module_loop) != SR_SUCCESS) {
		sal_printf("failed to start sr_module_loop\n");
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

