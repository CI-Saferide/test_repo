#include "sr_tasks.h"
#include "sr_sal_common.h"

typedef struct {
	void* data;
	SR_BOOL run;
	void (*pre_stop_cb) (void);
} sr_task;

sr_task sr_tasks_array[SR_TOTAL_TASKS];

SR_8 *task_names[SR_TOTAL_TASKS] = {
	"SR_ENGINE",
	"SR_MODULE",
	"SR_CAN_COLLECT",
	"SR_INFO_GATHER",
};

SR_32 sr_stop_task(sr_task_type task_id)
{
	if (task_id > SR_MAX_TASK) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sal_stop_task: invalid task_id %d",REASON,
			task_id);
		return SR_ERROR;
	}

	if (!sr_tasks_array[task_id].run) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sr_stop_task: task %s already stopped",REASON,
			task_names[task_id]);
		return SR_SUCCESS;
	}

	CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
		"%s=sr_stop_task: stopping task %s", REASON,
		task_names[task_id]);
	sr_tasks_array[task_id].run = 0;

	if (sr_tasks_array[task_id].pre_stop_cb)
		sr_tasks_array[task_id].pre_stop_cb();
	if (sal_task_stop(sr_tasks_array[task_id].data) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sal_stop_task: failed to stop task %s", REASON,
			task_names[task_id]);
		return SR_ERROR;
	}

	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
		"%s=sr_stop_task: task %s stopped",MESSAGE,
		task_names[task_id]);

	return SR_SUCCESS;
}

SR_32 sr_task_set_pre_stop_cb(sr_task_type task_id,void (*pre_stop_cb)(void))
{
	if (task_id > SR_MAX_TASK) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sal_stop_task: invalid task_id %d",REASON, task_id);
		return SR_ERROR;
	}

	sr_tasks_array[task_id].pre_stop_cb = pre_stop_cb;

	return SR_SUCCESS;
}

SR_32 sr_start_task(sr_task_type task_id,SR_32 (*task_func)(void *data))
{
	if (task_id > SR_MAX_TASK) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
			"%s=sal_stop_task: invalid task_id %d",MESSAGE,
			task_id);
		return SR_ERROR;
	}

	if (sr_tasks_array[task_id].run) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sr_stop_task: task %s already running",REASON,
			task_names[task_id]);
		return SR_SUCCESS;
	}

	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
		"%s=sal_start_task: starting task %s",MESSAGE,
		task_names[task_id]);
	sr_tasks_array[task_id].run = SR_TRUE;

	if (sal_task_start(&sr_tasks_array[task_id].data, task_func) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sal_start_task: failed to create thread for %s",REASON,
			task_names[task_id]);
		sr_tasks_array[task_id].run = SR_FALSE;
		return SR_ERROR;
	}

	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
		"%s=sal_start_task: task %s started. data 0x%p",MESSAGE,
		task_names[task_id], sr_tasks_array[task_id].data);

	return SR_SUCCESS;
}

SR_BOOL sr_task_should_stop(sr_task_type task_id)
{
	if (task_id > SR_MAX_TASK) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sr_task_should_stop: invalid task_id %d",REASON,
			task_id);
		return SR_FALSE;
	}

	return !sr_tasks_array[task_id].run;
}

SR_8* sr_task_get_name(sr_task_type task_id)
{
	if (task_id > SR_MAX_TASK) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sr_task_get_name: invalid task_id %d",REASON,
			task_id);
		return SR_FALSE;
	}

	return task_names[task_id];
}

void* sr_task_get_data(sr_task_type task_id)
{
	if (task_id > SR_MAX_TASK) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sr_task_get_data: invalid task_id %d",REASON,
			task_id);
		return 0;
	}

	return sr_tasks_array[task_id].data;
}

