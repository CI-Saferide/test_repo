#include "sr_stat_analysis.h"
#include "sr_ec_common.h"
#include "sr_event_collector.h"
#include "sr_stat_analysis_common.h"
#include "sr_shmem.h"

#define STAT_ANALYSIS_TRANSMIT_SCHEDULE_USECS 1000000
#define STAT_ANALYSIS_GC_SCHEDULE_USECS       10000000
#define STAT_ANALYSIS_WATCHDOG_SCHEDULE_USECS (SR_AGING_TIME * 1000000 * 2)
#define STAT_ANALYSIS_AGED_CLEANUP_SCHEDULE_USECS (SR_CONNECTIOLN_AGED_THRESHHOLD * 1000000)

static TASK_DESC *transmit_task;
static TASK_DESC *garbage_collector_task;
static TASK_DESC *watchdog_task;
static TASK_DESC *aged_cleanup_task;
static SR_BOOL is_run_transmit = SR_FALSE;
static SR_BOOL is_run_garbage_collector = SR_FALSE;
#if 0
static SR_BOOL is_run_watchdog = SR_FALSE;
#endif
static SR_BOOL is_run_aged_cleanup = SR_FALSE;
static SR_TIME_COUNT last_time_message_recived;
static SR_BOOL is_stat_analysis_um_running = SR_TRUE;

SR_BOOL sr_stat_analysis_um_is_running(void)
{	
	return is_stat_analysis_um_running;
}

static SR_32 sr_stat_analysis_transmit_task(void *data)
{
	while (is_run_transmit) {
        	sal_schedule_timeout(STAT_ANALYSIS_TRANSMIT_SCHEDULE_USECS);
#ifdef SR_STAT_ANALYSIS_DEBUG
		sal_kernel_print_info("STAT ANALYSIS TRANSMIT is_stat_analysis_um_running:%d\n", is_stat_analysis_um_running);
#endif
		if (is_stat_analysis_um_running)
 	       		sr_stat_analysis_start_transmit();
	}

	return SR_SUCCESS;
}

static SR_32 sr_stat_analysis_garbage_collector_task(void *data)
{
	while (is_run_garbage_collector) {
        	sal_schedule_timeout(STAT_ANALYSIS_GC_SCHEDULE_USECS);
		sr_stat_analysis_garbage_collector();
	}

	return SR_SUCCESS;
}

#if 0
static SR_32 sr_stat_analysis_watchdog_task(void *data)
{
	while (is_run_watchdog) {
        	sal_schedule_timeout(STAT_ANALYSIS_WATCHDOG_SCHEDULE_USECS);
		if (sal_elapsed_time_secs(is_stat_analysis_um_running) >  3 * SR_AGING_TIME) {
			sal_kernel_print_info("STAT ANALYSIS Watchdog shutdown \n");
			is_stat_analysis_um_running = SR_FALSE;
		}
	}

	return SR_SUCCESS;
}
#endif

static SR_32 sr_stat_analysis_aged_cleanup_task(void *data)
{
        while (is_run_aged_cleanup) {
                sal_schedule_timeout(STAT_ANALYSIS_AGED_CLEANUP_SCHEDULE_USECS);
		sr_stat_connection_aging_cleanup();
        }

        return SR_SUCCESS;
}   

SR_32 sr_stat_analysis_init(void)
{
	SR_32 rc = SR_SUCCESS;

	sal_update_time_counter(&last_time_message_recived);

	if ((rc = sr_stat_port_init()) != SR_SUCCESS) {
		sal_kernel_print_err("sr_stat_analysis_init sr_stat_port_init FAILED\n");
		return rc;
	}
	if ((rc = sr_stat_connection_init()) != SR_SUCCESS) {
		sal_kernel_print_err("sr_stat_analysis_init sr_stat_connection_init FAILED\n");
		goto error_connection;
	}
	if ((rc = sal_task_start((void **)&transmit_task, sr_stat_analysis_transmit_task)) != SR_SUCCESS) {
		sal_kernel_print_err("sr_stat_analysis_init sal_task_start for sr_stat_analysis_transmit_task FAILED\n");
		goto error_transmit;
	}
	is_run_transmit = SR_TRUE;
	if ((rc = sal_wake_up_process(transmit_task)) != SR_SUCCESS) {
		sal_kernel_print_err("sr_stat_analysis_init sal_task_start for sr_stat_analysis_transmit_task FAILED\n");
		goto error_transmit_wakeup;
	}
	if ((rc = sal_task_start((void **)&garbage_collector_task, sr_stat_analysis_garbage_collector_task)) != SR_SUCCESS) {
		sal_kernel_print_err("sr_stat_analysis_init sal_task_start for sr_stat_analysis_garbage_collector_task FAILED\n");
		goto error_transmit_wakeup;
	}
	is_run_garbage_collector = SR_TRUE;
	if ((rc = sal_wake_up_process(garbage_collector_task)) != SR_SUCCESS) {
		sal_kernel_print_err("sr_stat_analysis_init sal_task_start for sr_stat_analysis_garbage_collector_task FAILED\n");
		goto error_gc_wakeup;
	}
	is_stat_analysis_um_running = SR_TRUE;
#if 0
	is_run_watchdog = SR_TRUE;
	if ((rc = sal_task_start((void **)&watchdog_task, sr_stat_analysis_watchdog_task)) != SR_SUCCESS) {
		sal_kernel_print_err("sr_stat_analysis_init sal_task_start for sr_stat_analysis_watchdog_task FAILED\n");
		goto error_gc_wakeup;
	}
	if ((rc = sal_wake_up_process(watchdog_task)) != SR_SUCCESS) {
		sal_kernel_print_err("sr_stat_analysis_init sal_task_start for sr_stat_analysis_watchdog_task FAILED\n");
		goto error_watchdog_wakeup;
	}
#endif
	is_run_aged_cleanup = SR_TRUE;
	if ((rc = sal_task_start((void **)&aged_cleanup_task, sr_stat_analysis_aged_cleanup_task)) != SR_SUCCESS) {
		sal_kernel_print_err("sr_stat_analysis_init sal_task_start for sr_stat_analysis_aged_cleanup_task FAILED\n");
		goto error_gc_wakeup;
	}
	if ((rc = sal_wake_up_process(aged_cleanup_task)) != SR_SUCCESS) {
		sal_kernel_print_err("sr_stat_analysis_init sal_task_start for sr_stat_analysis_aged_cleanup_task FAILED\n");
		goto error_aged_wakeup;
	}

	goto out;

error_aged_wakeup:
	is_run_aged_cleanup = SR_FALSE;
	sal_task_stop(aged_cleanup_task);
#if 0
error_watchdog_wakeup:
	is_run_watchdog = SR_FALSE;
	sal_task_stop(watchdog_task);
#endif
error_gc_wakeup:
	is_run_garbage_collector = SR_FALSE;
	sal_task_stop(garbage_collector_task);
error_transmit_wakeup:
	is_run_transmit = SR_FALSE;
	sal_task_stop(transmit_task);
error_transmit:
	sr_stat_connection_uninit();
error_connection:
	sr_stat_port_uninit();

out:
	return rc;
}

void sr_stat_analysis_uninit(void)
{
	is_run_aged_cleanup = SR_FALSE;
	sal_task_stop(aged_cleanup_task);
#if 0
	is_run_watchdog = SR_FALSE;
	sal_task_stop(watchdog_task);
#endif
	is_run_transmit = SR_FALSE;
	sal_task_stop(transmit_task);
	is_run_garbage_collector = SR_FALSE;
	sal_task_stop(garbage_collector_task);
	sr_stat_connection_uninit();
}

#ifdef SR_STS_ANALYSIS_DEBUG
void sr_stat_analisys_print_connections(SR_BOOL is_print_LRU)
{
	sal_kernel_print_info("The connection table:\n");
	sr_stat_connection_print(is_print_LRU);
}
#endif

SR_32 sr_stat_analysis_start_transmit(void)
{
	return sr_connection_transmit();
}

void sr_stat_analysis_report_porcess_die(SR_U32 pid)
{
        struct sr_ec_process_died_t pdocess_died = {};

        pdocess_died.pid = pid;
        sr_ec_send_event(MOD2ENG_BUF, SR_EVENT_PROCESS_DIED, &pdocess_died);
}

SR_32 sr_stat_analysis_handle_message(struct sr_stat_analysis_msg *msg)
{
	sal_update_time_counter(&last_time_message_recived);
	is_stat_analysis_um_running = SR_TRUE;
	switch (msg->msg_type) {
		case SR_STAT_ANALYSIS_CONNECTION_DIED:
			sr_stat_connection_soft_delete(&(msg->con_id));
			break;
		case SR_STAT_ANALYSIS_KEEP_ALIVE:
#ifdef SR_STAT_ANALYSIS_DEBUG
			CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
				"STAT ANALYSIS got keepalive \n");
#endif
			break;
		default:
			break;
	}

	return SR_SUCCESS;
}

void sr_stat_analysis_garbage_collector(void)
{
	sr_stat_connection_garbage_collection();
}

