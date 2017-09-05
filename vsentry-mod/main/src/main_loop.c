#include "sal_module.h"
#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_msg_dispatch.h"
#include "sr_tasks.h"
#include "main_loop.h"
#include "sr_sal_common.h"
#include "sr_classifier.h"
#include "sr_cls_file.h"
#include "sr_cls_network.h"
#include "sr_cls_canid.h"
#include "sr_cls_port.h"
#include "sr_control.h"

#define MAX_RX_MSG_LEN 	512

SR_32 sr_module_loop(void *arg)
{
	sr_shmem* vsshmem;
	SR_32 ret;
	char *msg;

	sal_printf("module_loop: started ...\n");

	while (!sr_task_should_stop(SR_MODULE_TASK)) {
		/* get the rx buffer ptr */
		vsshmem = sr_msg_get_buf(ENG2MOD_BUF);

		/* if allocated (i.e. engine started ... */
		if (vsshmem && vsshmem->buffer) {
			/* check for incoming msgs from engine */
			while ((msg = (char *)sr_read_msg(ENG2MOD_BUF, &ret)) > 0) {
				/* TODO: Currently reading hardcoded file classifier messages which are always 17 bytes. later needs a different implementation */
				sr_msg_dispatch((char*)msg, ret);
				sr_free_msg(ENG2MOD_BUF);
			}

			/* short sleep (>2ms) to allow others to run so they 
			   could fill the buffer */;
			sal_schedule_timeout(5*1000);
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

SR_32 sr_msg_dispatch(char *msg, int size)
{
	sr_msg_dispatch_hdr_t *hdr = (sr_msg_dispatch_hdr_t *)msg;
	if (!hdr)
		return SR_ERROR;
	switch (hdr->msg_type) {
		case SR_MSG_TYPE_CLS_RULES:
			sr_cls_rules_msg_dispatch((struct sr_cls_rules_msg *)hdr->msg_payload);
			break;	
		case SR_MSG_TYPE_CLS_FILE:
			sr_cls_file_msg_dispatch((struct sr_cls_file_msg *)hdr->msg_payload);
			break;
		case SR_MSG_TYPE_CLS_NETWORK: {
			sr_cls_network_msg_dispatch((struct sr_cls_network_msg *)hdr->msg_payload);
			}
			break;
		case SR_MSG_TYPE_CLS_UID:
			sr_cls_uid_msg_dispatch((struct sr_cls_uid_msg *)hdr->msg_payload);
			break;
		case SR_MSG_TYPE_CLS_CANBUS:
			sr_cls_canid_msg_dispatch((struct sr_cls_canbus_msg *)hdr->msg_payload);
			break;
		case SR_MSG_TYPE_CLS_PORT:
			sr_cls_port_msg_dispatch((struct sr_cls_port_msg *)hdr->msg_payload);
			break;
		case SR_MSG_TYPE_CONTROL:
			sr_control_msg_dispatch((struct sr_control_msg *)hdr->msg_payload);
			break;
		case SR_MSG_TYPE_CLS_CLEANUP_NOLOCK:
			sr_classifier_empty_tables(SR_FALSE);
			break;	
		case SR_MSG_TYPE_DEFAULT:
			sal_printf("wrong msg_type\n");
			break;
	}

	return SR_SUCCESS;

}
