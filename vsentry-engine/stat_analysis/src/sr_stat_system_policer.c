#include "sr_stat_system_policer.h"
#include <sr_gen_hash.h>
#include <sal_mem.h>
#include <stdio.h>
#include "sr_stat_analysis.h"
#include "sr_config_parse.h"

#define HASH_SIZE 500

static struct sr_gen_hash *system_policer_table, *system_policer_learn_table;

static SR_U64 cur_time;
static SR_BOOL is_updated = SR_FALSE;
static SR_U8 system_policer_interval;

typedef struct system_policer_item  {
	char exec[SR_MAX_PATH_SIZE];
	SR_U64 time_stamp;
	struct sr_ec_system_stat_t stats;
} system_policer_item_t;

static SR_32 system_policer_comp(void *data_in_hash, void *comp_val)
{
        system_policer_item_t *system_policer_item = (system_policer_item_t *)data_in_hash;
	char *comp_exe = (char *)comp_val;

        if (!data_in_hash)
                return -1;

	return strncmp(system_policer_item->exec, comp_exe, SR_MAX_PATH_SIZE);
}

static void system_policer_print(void *data_in_hash)
{
	system_policer_item_t *system_policer_item = (system_policer_item_t *)data_in_hash;

        CEF_log_event(SR_CEF_CID_SP, "info", SEVERITY_LOW, "process :%s: utime:%d stime:%d vm_allocated:%d bytes_read:%d bytes_write:%d num of threads:%d curr_time:%d",
		system_policer_item->exec, system_policer_item->stats.utime, system_policer_item->stats.stime,
		system_policer_item->stats.vm_allocated,  
		system_policer_item->stats.bytes_read, system_policer_item->stats.bytes_write,
		system_policer_item->stats.num_of_threads, system_policer_item->stats.curr_time);
}

static SR_U32 system_policer_create_key(void *data)
{
	system_policer_item_t *system_policer_item = (system_policer_item_t *)data;
	SR_U32 num = 0, len, i;
	// TODO : Ctreate a better hash key creation function.
	
	len = strlen(system_policer_item->exec);
	for (i = 0; i < len; i++)
		num += system_policer_item->exec[i]; 

	return num;
}

#ifdef SYSTEM_POLICER_DEBUG
static SR_BOOL is_debug_exe(char *exe)
{
	return (SR_BOOL)!!strstr(exe, "system_test_process");
}
#endif /* SYSTEM_POLICER_DEBUG */

SR_32 sr_stat_system_policer_init(void)
{
	hash_ops_t hash_ops = {};
	struct config_params_t *config_params;

	config_params = sr_config_get_param();
	system_policer_interval = config_params->system_policer_interval;
	hash_ops.create_key = system_policer_create_key;
	hash_ops.comp = system_policer_comp;
	hash_ops.print = system_policer_print;
	if (!(system_policer_table = sr_gen_hash_new(HASH_SIZE, hash_ops, 0))) {
        	CEF_log_event(SR_CEF_CID_SP, "error", SEVERITY_HIGH, "%s=insertion to system policer hash has failed", REASON);
		return SR_ERROR;
	}
	if (!(system_policer_learn_table = sr_gen_hash_new(HASH_SIZE, hash_ops, 0))) {
        	CEF_log_event(SR_CEF_CID_SP, "error", SEVERITY_HIGH, "%s=insertion to system policer hash has failed", REASON);
		return SR_ERROR;
	}

        return SR_SUCCESS;
}

void sr_stat_system_policer_uninit(void)
{
        sr_gen_hash_destroy(system_policer_table);
        sr_gen_hash_destroy(system_policer_learn_table);
}

static SR_32 write_leran_to_file(void *hash_data, void *data)
{
	FILE *fp = (FILE *)data;
	system_policer_item_t *learn = (system_policer_item_t *)hash_data;

	fprintf(fp, "%s,%llu,%llu,%llu,%llu,%u,%u\n", learn->exec, learn->stats.utime, learn->stats.stime, learn->stats.bytes_read, learn->stats.bytes_write,
		learn->stats.vm_allocated, learn->stats.num_of_threads);

	return SR_SUCCESS;
}

static SR_32 system_policer_flush_leran_table(void)
{
	struct config_params_t *config_params;
	FILE *fp;

	config_params = sr_config_get_param();

	if (!(fp = fopen(config_params->system_prolicer_learn_file, "w"))) {
        	CEF_log_event(SR_CEF_CID_SP, "error", SEVERITY_HIGH, "%s=system_policer_flush_leran_table failed oppening:%",
			REASON, config_params->system_prolicer_learn_file);
		return SR_ERROR;
	}
	sr_gen_hash_exec_for_each(system_policer_learn_table, write_leran_to_file, fp, 0); 

	fclose(fp);

	return SR_SUCCESS;
}

#define SET_MAX_DIF_FIELD(curr, prev, max, ctime, ptime) \
	if ((ctime - ptime) / (system_policer_interval * 1000) > 0) {\
		value = (curr - prev) / ((ctime - ptime) / (system_policer_interval * 1000));\
		if (value > max) { \
			max = value; \
			is_updated = SR_TRUE; \
		} \
	}

#define SET_MAX_FIELD(curr, max) \
	if (curr > max) { \
		max = curr; \
		is_updated = SR_TRUE; \
	}

#define SET_MAX_DIF_FIELD_PROTECT(curr, prev, max, ctime, ptime, exe, fieldname) \
	if ((ctime - ptime) / (system_policer_interval * 1000) > 0) {\
		value = (curr - prev) / ((ctime - ptime) / (system_policer_interval * 1000));\
		max_tol = max * (1 + config_params->system_policer_threshold_percent / 100.0);\
		if (value > max) { \
			if (value < max_tol) { \
				max = value; \
				is_updated = SR_TRUE; \
			} else {\
                		CEF_log_event(SR_CEF_CID_SP, "system policer alert", SEVERITY_MEDIUM, \
					"%s=%s %s=%s %s=expected %d measured %d %s=%d", \
					DEVICE_EVENT_CATEGORY, fieldname, DEVICE_PROCESS_NAME, exe, REASON, max, value, BASE_EVENT_COUNT, ++count);\
			} \
		} \
	}

#define SET_MAX_FIELD_PROTECT(curr, max, exe, fieldname) \
	max_tol = max * (1 + config_params->system_policer_threshold_percent / 100.0);\
	if (curr > max) { \
		if (curr < max_tol) { \
			max = curr; \
			is_updated = SR_TRUE; \
		} else { \
                	CEF_log_event(SR_CEF_CID_SP, "system policer alert", SEVERITY_MEDIUM, \
				"%s=%s %s=%s %s=expected %d measured %d %s=%d", \
				DEVICE_EVENT_CATEGORY, fieldname, DEVICE_PROCESS_NAME, exe, REASON, max, curr, BASE_EVENT_COUNT, ++count);\
		}\
	}

static SR_32 system_policer_update_max(char *exe, struct sr_ec_system_stat_t *curr, struct sr_ec_system_stat_t *prev, struct sr_ec_system_stat_t *max)
{
	SR_U64 value;

	SET_MAX_DIF_FIELD(curr->utime, prev->utime, max->utime, curr->curr_time, prev->curr_time)
	SET_MAX_DIF_FIELD(curr->stime, prev->stime, max->stime, curr->curr_time, prev->curr_time)
	SET_MAX_DIF_FIELD(curr->bytes_read, prev->bytes_read, max->bytes_read, curr->curr_time, prev->curr_time)
	SET_MAX_DIF_FIELD(curr->bytes_write, prev->bytes_write, max->bytes_write, curr->curr_time, prev->curr_time)

	SET_MAX_FIELD(curr->num_of_threads, max->num_of_threads)
	SET_MAX_FIELD(curr->vm_allocated, max->vm_allocated)

	return SR_SUCCESS;
}

static SR_32 system_policer_update_tolerance(char *exe, struct sr_ec_system_stat_t *curr, struct sr_ec_system_stat_t *prev, struct sr_ec_system_stat_t *max)
{
	struct config_params_t *config_params;
	SR_U64 value;
	SR_U32 max_tol, count = 0;

        config_params = sr_config_get_param();

	SET_MAX_DIF_FIELD_PROTECT(curr->utime, prev->utime, max->utime, curr->curr_time, prev->curr_time, exe, "utime")
	SET_MAX_DIF_FIELD_PROTECT(curr->stime, prev->stime, max->stime, curr->curr_time, prev->curr_time, exe, "stime")
	SET_MAX_DIF_FIELD_PROTECT(curr->bytes_read, prev->bytes_read, max->bytes_read, curr->curr_time, prev->curr_time, exe, "bytes_read")
	SET_MAX_DIF_FIELD_PROTECT(curr->bytes_write, prev->bytes_write, max->bytes_write, curr->curr_time, prev->curr_time, exe, "bytes_write")

	SET_MAX_FIELD_PROTECT(curr->num_of_threads, max->num_of_threads, exe, "num_of_threads")

#ifdef SYSTEM_POLICER_DEBUG
	if (is_debug_exe(exe)) {
		printf("PPPPPPPPPPPPPPPPPPPPPPP System_policer_update_tolerance exec:%s threshold:%d max:%d max_tol:%d count:%d\n",
			exe, config_params->system_policer_threshold_percent, max->utime, max_tol, count);
	}
#endif

	return SR_SUCCESS;
}

static SR_32 system_policer_learn(char *exe_name, system_policer_item_t *system_policer_item, struct sr_ec_system_stat_t *stats)
{
	system_policer_item_t *system_policer_learn_item;

#ifdef SYSTEM_POLICER_DEBUG
	if (is_debug_exe(exe_name)) {
		printf("LLLLLLLLLLLLLLLLLLLLLLLLL exe:%s utime:%d bytes read:%llu !!!!!\n", exe_name, stats->utime, stats->bytes_read);
	}
#endif

	if (!(system_policer_learn_item = sr_gen_hash_get(system_policer_learn_table, exe_name, 0))) {
		SR_Zalloc(system_policer_learn_item, system_policer_item_t *, sizeof(system_policer_item_t));
		if (!system_policer_learn_item) {
        		CEF_log_event(SR_CEF_CID_SP, "error", SEVERITY_HIGH, "%s=learn hash update: memory allocation failed", REASON);
			return SR_ERROR;
		}
		strncpy(system_policer_learn_item->exec, exe_name, SR_MAX_PATH_SIZE);
		if (sr_gen_hash_insert(system_policer_learn_table, (void *)exe_name, system_policer_learn_item, 0) != SR_SUCCESS) {
        		CEF_log_event(SR_CEF_CID_SP, "error", SEVERITY_HIGH, "%s=system policer learn insert to hash failed", REASON);
			return SR_ERROR;
		}	
		system_policer_learn_item = sr_gen_hash_get(system_policer_learn_table, exe_name, 0);
	}
#ifdef SYSTEM_POLICER_DEBUG
	if (is_debug_exe(exe_name)) {
		printf("LLLLLLLLLSSSSS NOT First  exe:%s stats utime:%d item utime:%llu diff:%llu bytes read diff:%llu time diff:%llu !!!!!\n", exe_name, 
			stats->utime, system_policer_item->stats.utime,
			stats->utime - system_policer_item->stats.utime, stats->bytes_read - system_policer_item->stats.bytes_read, stats->curr_time - system_policer_item->stats.curr_time);
	}
#endif
	system_policer_update_max(exe_name, stats, &(system_policer_item->stats), &(system_policer_learn_item->stats));

	return SR_SUCCESS;
}

static SR_32 system_policer_protect(char *exe_name, system_policer_item_t *system_policer_item, struct sr_ec_system_stat_t *stats)
{
	system_policer_item_t *system_policer_learn_item;

#ifdef SYSTEM_POLICER_DEBUG
	if (is_debug_exe(exe_name)) {
		printf("\nPPPPPPPPPPPPPPPPPPPPPPPPPPPP exe:%s utime:%d bytes_read:%llu !!!!!\n", exe_name, stats->utime, stats->bytes_read);
	}
#endif

	if (!(system_policer_learn_item = sr_gen_hash_get(system_policer_learn_table, exe_name, 0))) {
		/* A binary that was never learned is running - Alert !! */
               	CEF_log_event(SR_CEF_CID_SP, "system policer alert", SEVERITY_MEDIUM, 
				"%s=%s %s=Unknown binary has been detecetd", DEVICE_PROCESS_NAME, exe_name, REASON);
		return SR_SUCCESS;
	}
#ifdef SYSTEM_POLICER_DEBUG
	if (is_debug_exe(exe_name)) {
		printf("PPPPPPPPPPPPPPPPP from system policer learn exe:%s stats utime:%d item utime:%d  diff:%d bytes_read:%llu bytes_read diff :%llu !!!!!\n", exe_name, 
			stats->utime, system_policer_item->stats.utime,
			stats->utime - system_policer_item->stats.utime, system_policer_item->stats.bytes_read,
			stats->bytes_read - system_policer_item->stats.bytes_read);
	}
#endif
	system_policer_update_tolerance(exe_name, stats, &(system_policer_item->stats), &(system_policer_learn_item->stats));

	return SR_SUCCESS;
}

SR_32 sr_stat_system_policer_new_data(struct sr_ec_system_stat_t *stats)
{
	system_policer_item_t *system_policer_item, *system_policer_new_item;
	char exe_name[SR_MAX_PATH_SIZE];
	sr_stat_mode_t stat_mode = sr_stat_analysis_learn_mode_get();

	if (stat_mode != SR_STAT_MODE_LEARN && stat_mode != SR_STAT_MODE_PROTECT)
		return SR_SUCCESS;
	
	if (sal_get_process_name(stats->pid, exe_name, sizeof(exe_name)) != SR_SUCCESS)
		return SR_SUCCESS; // Process already removed.

        if (!(system_policer_item = sr_gen_hash_get(system_policer_table, exe_name, 0))) {
		/* Learning - Insert process to DB */
		SR_Zalloc(system_policer_new_item, system_policer_item_t *, sizeof(system_policer_item_t));
		if (!system_policer_new_item) {
        		CEF_log_event(SR_CEF_CID_SP, "error", SEVERITY_HIGH, "%s=learn hash update: memory allocation failed", REASON);
			return SR_ERROR;
		}
		strncpy(system_policer_new_item->exec, exe_name, SR_MAX_PATH_SIZE);
		system_policer_new_item->stats = *stats;
		system_policer_new_item->time_stamp = sal_get_time();
#ifdef SYSTEM_POLICER_DEBUG 
		if (is_debug_exe(exe_name)) {
				printf("\nL1 ####################>>> B4 INERT from system_policer !!!!>> exec:%s: ", system_policer_new_item->exec);
				printf("> utime:%llu stime:%llu read:%llu: :bytes write:%llu: \n",
						system_policer_new_item->stats.utime, system_policer_new_item->stats.stime, system_policer_new_item->stats.bytes_read,
						system_policer_new_item->stats.bytes_write);
		}
#endif
		if (sr_gen_hash_insert(system_policer_table, (void *)exe_name, system_policer_new_item, 0) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SP, "error", SEVERITY_HIGH, "%s=sr_gen_hash_insert failed", REASON);
			return SR_ERROR;
		}	
		
		/* Start to learn from second process data sample */
		return SR_SUCCESS;
	}

	/* If pid is not the same - New process, start learn from next sample */
	if (system_policer_item->stats.pid != stats->pid)
		goto out;
	/* If threads died */
	if (stats->utime < system_policer_item->stats.utime ||
	    stats->stime < system_policer_item->stats.stime)  {
		goto out;
	}

	/* Existing binaric */
	switch (stat_mode) {
		case SR_STAT_MODE_LEARN:
			if (system_policer_learn(exe_name, system_policer_item, stats) != SR_SUCCESS) {
        			CEF_log_event(SR_CEF_CID_SP, "error", SEVERITY_HIGH, "%s=system_policer_learn failed", REASON);
				return SR_ERROR;
			}
			break;
		case SR_STAT_MODE_PROTECT:
			if (system_policer_protect(exe_name, system_policer_item, stats) != SR_SUCCESS) {
        			CEF_log_event(SR_CEF_CID_SP, "error", SEVERITY_HIGH, "%s=system_policer_protect failed", REASON);
				return SR_ERROR;
			}
			break;
		default:
			break;
	}

out:
	system_policer_item->stats = *stats;
	system_policer_item->time_stamp = sal_get_time();

	return SR_SUCCESS;
}

SR_32 sr_start_system_policer_data_finish(void)
{
	SR_32 rc;

	if (!is_updated)
		return SR_SUCCESS;
	is_updated = SR_FALSE;

	// Write the learned table to a file
	if ((rc = system_policer_flush_leran_table()) != SR_SUCCESS) {
		return rc;
	}
	
	return SR_SUCCESS;
}

void sr_stat_system_policer_print(void)
{
	sr_gen_hash_print(system_policer_table);
}

void sr_stat_system_policer_learn_print(void)
{
	sr_gen_hash_print(system_policer_learn_table);
}

static SR_BOOL is_process_aged(void *hash_data)
{
        system_policer_item_t *system_policer_item = (system_policer_item_t *)hash_data;

	if (cur_time - system_policer_item->time_stamp > SR_SYSTEM_POLICER_AGED_THRESHHOLD) {
#ifdef SYSTEM_POLICER_DEBUG
		printf("Exec %s AGED DELETED \n", system_policer_item->exec);
#endif
                return SR_TRUE; // Delete the process entry -  to old...
	}
        return SR_FALSE;
}

SR_32 sr_stat_system_policer_delete_aged(void)
{
	cur_time = sal_get_time();

	sr_gen_hash_delete_all_cb(system_policer_table, is_process_aged);

	return SR_SUCCESS;
}

#define GET_NUM_TOKEN(field) \
		token = strtok(NULL, ",");\
		if (!token)\
			continue;\
		field = atoi(token);

SR_32 sr_stat_policer_load_file(void)
{
	ssize_t read;
	FILE *fp;
	size_t len = 0;
	char *line = NULL;
	struct config_params_t *config_params;
	system_policer_item_t *system_policer_learn_item;
	char *token, *exe_name;

	config_params = sr_config_get_param();
	
	if (!(fp = fopen(config_params->system_prolicer_learn_file, "r"))) {
        	CEF_log_event(SR_CEF_CID_SP, "error", SEVERITY_HIGH, "%s=sr_stat_policer_load_fileailed oppening:%s ",
			REASON, config_params->system_prolicer_learn_file);
		return SR_ERROR;
	}

	while ((read = getline(&line, &len, fp)) != -1) {
#ifdef SYSTEM_POLICER_DEBUG
        	printf("Retrieved line of length %zu :\n", read);
        	printf("%s", line);
#endif
		SR_Zalloc(system_policer_learn_item, system_policer_item_t *, sizeof(system_policer_item_t));
		if (!system_policer_learn_item) {
        		CEF_log_event(SR_CEF_CID_SP, "error", SEVERITY_HIGH, "%s=learn hash update: memory allocation failed ", REASON);
			return SR_ERROR;
		}
		exe_name = strtok(line, ",");
		if (!exe_name)
			continue;
		strncpy(system_policer_learn_item->exec, exe_name, SR_MAX_PATH_SIZE);
		GET_NUM_TOKEN(system_policer_learn_item->stats.utime)
		GET_NUM_TOKEN(system_policer_learn_item->stats.stime)
		GET_NUM_TOKEN(system_policer_learn_item->stats.bytes_read)
		GET_NUM_TOKEN(system_policer_learn_item->stats.bytes_write)
		GET_NUM_TOKEN(system_policer_learn_item->stats.vm_allocated)
		GET_NUM_TOKEN(system_policer_learn_item->stats.num_of_threads)
		if (sr_gen_hash_insert(system_policer_learn_table, (void *)exe_name, system_policer_learn_item, 0) != SR_SUCCESS) {
        		CEF_log_event(SR_CEF_CID_SP, "error", SEVERITY_HIGH, "%s=sr_gen_hash_insert failed ", REASON);
			return SR_ERROR;
		}	
	}

	fclose(fp);
	if (len)
		free(line);

	return SR_SUCCESS;
}

