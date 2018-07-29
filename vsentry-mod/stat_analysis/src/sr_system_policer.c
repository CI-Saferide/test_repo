#include "sr_system_policer.h"
#include "sal_linux.h"
#include "sr_ec_common.h"
#include "sr_shmem.h"
#include "sr_event_collector.h"
#include "sr_control.h"

#ifdef SYSTEM_POLICER_DEBUG
int my_pid = 47591;
#endif

static SR_32 transmit_task(void *p)
{
	struct sr_ec_system_stat_t *system_stat = (struct sr_ec_system_stat_t *)p;
	SR_32 rc;

#ifdef SYSTEM_POLICER_DEBUG
	if (system_stat->pid == my_pid) {
		printk("XXXXXXX DEBUG in transmit_task CB pid:%d utime:%llu stime:%llu vm_allcated:%d num of threrads:%d bytes_write:%d bytes_read:%d \n",
			system_stat->pid, system_stat->utime, system_stat->stime, system_stat->vm_allocated, system_stat->num_of_threads,
			system_stat->bytes_write, system_stat->bytes_read);
	}
#endif

	 rc = sr_ec_send_event(MOD2STAT_BUF, SR_EVENT_STATS_SYSTEM, system_stat);

	return rc;
}

SR_32 sr_system_policer_start_transmit(void)
{
	struct sr_ec_system_finish_t system_finish = {};
	static SR_U8 count;
	struct config_params_t *config_params = sr_control_config_params();

	/* System policer transmition is NOT done on every stransmission */
	count++;
	if (count < config_params->system_policer_interval)
		return SR_SUCCESS;
	count = 0;

	// Transmission	
	sal_exec_for_all_tasks(transmit_task);
	sr_ec_send_event(MOD2STAT_BUF, SR_EVENT_STATS_SYSTEM_FINISH, &system_finish);

	return SR_SUCCESS;
}
