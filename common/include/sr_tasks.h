#ifndef __SR_TASKS__
#define __SR_TASKS__

#include "sr_types.h"

typedef enum {
	SR_ENGINE_TASK = 0,
	SR_MODULE_TASK,
	SR_LOG_TASK,
	SR_MAX_TASK = SR_LOG_TASK,
	SR_TOTAL_TASKS = (SR_MAX_TASK + 1),
} sr_task_type;

SR_32 sr_stop_task(sr_task_type task_id);
SR_32 sr_start_task(sr_task_type task_id, SR_32 (*task_func)(void *data));
SR_BOOL sr_task_should_stop(sr_task_type task_id);
SR_8* sr_task_get_name(sr_task_type task_id);
void* sr_task_get_data(sr_task_type task_id);

#endif /* __SR_TASKS__ */