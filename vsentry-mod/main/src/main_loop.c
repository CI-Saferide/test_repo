#include "sal_module.h"
#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_msg_dispatch.h"
#include "sr_tasks.h"
#include "main_loop.h"
#include "sr_sal_common.h"
#include "sr_cls_file.h"
#include "sr_cls_network.h"

#define MAX_RX_MSG_LEN 	512

SR_32 sr_module_loop(void *arg)
{
	sr_shmem* vsshmem;
	SR_32 ret;
	sr_msg_cls_t *msg;

	sal_printf("module_loop: started ...\n");

	while (!sr_task_should_stop(SR_MODULE_TASK)) {
		/* get the rx buffer ptr */
		vsshmem = sr_msg_get_buf(ENG2MOD_BUF);

		/* if allocated (i.e. engine started ... */
		if (vsshmem && vsshmem->buffer) {
			/* check for incoming msgs from engine */
			while ((msg = (sr_msg_cls_t*)sr_read_msg(ENG2MOD_BUF, &ret)) > 0) {
				/* TODO: Currently reading hardcoded file classifier messages which are always 17 bytes. later needs a different implementation */
				sr_msg_dispatch((char*)msg, ret);
				switch (msg->msg_type) {
				case SR_MSG_TYPE_CLS_FILE:
					sal_printf("MSG type CLS_FILE ");
					switch (msg->sub_msg.msg_type) {
					case SR_CLS_INODE_INHERIT:
						sal_printf("[INODE_INHERIT] ");
						break;
					case SR_CLS_INODE_DEL_RULE:
						sal_printf("[INODE_DEL_RULE] ");
						break;
					case SR_CLS_INODE_ADD_RULE:
						sal_printf("[INODE_ADD_RULE] ");
						break;
					case SR_CLS_INODE_REMOVE:
						sal_printf("[INODE_REMOVE] ");
						break;
					default:
						sal_printf("wrong sub_msg->msg_type\n");
						break;
					} /* end of SR_MSG_TYPE_CLS_FILE */
					sal_printf("rulenum %d inode1 %d inode2 %d\n",
						msg->sub_msg.rulenum, msg->sub_msg.inode1, msg->sub_msg.inode2);
					break;
				case SR_MSG_TYPE_CLS_NETWORK:
					sal_printf("MSG type CLS_NETWORK ");
					switch (msg->sub_msg.msg_type) {
						case SR_CLS_IPV4_DEL_RULE:
						sal_printf("[IPV4_DEL] ");
						break;
						case SR_CLS_IPV4_ADD_RULE:
						sal_printf("[IPV4_ADD] ");
						break;
						case SR_CLS_IPV6_DEL_RULE:
						sal_printf("[IPV6_DEL] ");
						break;
						case SR_CLS_IPV6_ADD_RULE:
						sal_printf("[IPV6_DEL] ");
						break;
					default:
						sal_printf("wrong sub_msg->msg_type\n");
						break;
					} /* end of SR_MSG_TYPE_CLS_NETWORK */
					break;
				case SR_MSG_TYPE_DEFAULT:
					break;
				}
				sr_free_msg(ENG2MOD_BUF);
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

SR_32 sr_msg_dispatch(char *msg, int size)
{
	sr_msg_dispatch_hdr_t *hdr = (sr_msg_dispatch_hdr_t *)msg;
	if (!hdr)
		return SR_ERROR;
	if (hdr->msg_type == SR_MSG_TYPE_CLS_FILE) {
		sr_cls_file_msg_dispatch((struct sr_cls_msg *)hdr->msg_payload);
	} else if (hdr->msg_type == SR_MSG_TYPE_CLS_NETWORK) {
		sr_cls_network_msg_dispatch((struct sr_cls_network_msg *)hdr->msg_payload);
	}
	return SR_SUCCESS;

}
