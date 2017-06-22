#include "sr_types.h"
#include "sr_tasks.h"
#include "sr_msg.h"
#include "sr_ring_buf.h"
#include "sr_engine_main.h"
#include "sr_sal_common.h"
#include "sr_log.h"

SR_32 engine_main_loop(void *data)
{
	SR_32 ret;
	SR_U8 msg[SR_MAX_PATH];

	sal_printf("engine_main_loop started\n");

	/* init the module2engine buffer*/
	ret = sr_msg_alloc_buf(MOD2ENG_BUF, (PAGE_SIZE * 2));
	if (ret != SR_SUCCESS){
		sal_printf("failed to init msg_buf\n");
		return SR_ERROR;
	}

	while (!sr_task_should_stop(SR_ENGINE_TASK)) {
		ret = sr_read_msg(MOD2ENG_BUF, msg, SR_MAX_PATH, SR_FALSE);
		if (ret > 0)
			sal_printf("MOD2ENG msg[len %d]\n", ret);

		if (ret == 0)
			usleep(1);
	}

	/* free allocated buffer */
	sr_msg_free_buf(MOD2ENG_BUF);

	sal_printf("engine_main_loop end\n");

	return SR_SUCCESS;
}

SR_32 sr_engine_start(void)
{
	SR_32 ret;

	sal_printf("Welcome to sr-engine App!\n");

	ret = sr_log_init("[VSENTRY]", 0);
	if (ret != SR_SUCCESS){
		sal_printf("failed to init sr_log\n");
		return SR_ERROR;
	}

	ret = sr_start_task(SR_ENGINE_TASK, engine_main_loop);
	if (ret != SR_SUCCESS){
		sal_printf("failed to start engine_main_loop\n");
		//sr_log_deinit();
		return SR_ERROR;
	}

	ret = sr_msg_alloc_buf(ENG2MOD_BUF, (PAGE_SIZE * 2));
	if (ret != SR_SUCCESS){
		sal_printf("failed to init msg_buf\n");
		return SR_ERROR;
	}

	//sr_cls_control_ut();

	while(1);

	/* TODO: */
	//sr_log_deinit();

	sr_stop_task(SR_ENGINE_TASK);

	return 0;
}
