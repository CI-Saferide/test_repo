#include "sr_cls_sk_process.h"
#include "sr_cls_network.h"
#include "sal_linux.h"
#include "sr_cls_conn_obj.h"

#define CLS_HOUSEKEEPING_SHCEDULE_USECS 90000000
static TASK_DESC *cls_housekeeping_task;
static SR_BOOL is_run_cls_housekeeping = SR_FALSE;

static SR_32 cls_housekeeping_task_func(void *data)
{
        while (is_run_cls_housekeeping) {
                sal_schedule_timeout(CLS_HOUSEKEEPING_SHCEDULE_USECS);
		sr_sk_process_cleanup();
		sr_conn_obj_cleanup();
		local_ips_array_init();
        }

        return SR_SUCCESS;
}

SR_32 sr_cls_housekeeping_init(void)
{
	if (sal_task_start((void **)&cls_housekeeping_task, cls_housekeeping_task_func) != SR_SUCCESS) {
  		sal_kernel_print_err("failed to initilize cls_housekeeping\n");
		return SR_ERROR;
        }
        is_run_cls_housekeeping = SR_TRUE;
        if (sal_wake_up_process(cls_housekeeping_task) != SR_SUCCESS) {
                sal_kernel_print_err("sr_cls_housekeeping_init sal_wake_up FAILED\n");
                sal_kernel_print_err("cls_housekeeping:failed to wakeup process\n");
        }

	return SR_SUCCESS;
}

void sr_cls_housekeeping_uninit(void)
{
        is_run_cls_housekeeping = SR_FALSE;
	sal_task_stop(cls_housekeeping_task);
}

