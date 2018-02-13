#include "sr_can_collector.h"
#include "sr_config_parse.h"
#include "engine_sal.h"

struct canTaskParams can_args = {.can_interface = DEFAULT_CAN0_INTERFACE, .can_print = SR_FALSE};

#define FILE_QUEUE 	99999
#define MAX_BUFF	256
const SR_8* disk = "/";
long long SAVE_SPACE;
long MAX_LOG_SIZE;

char prefix[MAX_BUFF]; 			/* prefix of the file, including VIN */
char file_candidate[MAX_BUFF]; 	/* filename of the current written log */ 
char postfix[] = "_.log";
int curr = 0;

struct candump_log log_arr[FILE_QUEUE];
char current_file[MAX_BUFF];

char buffer_TS[64];
time_t t;
struct tm tm;

void log_it(char* str)
{
    char mv_from[MAX_BUFF];
    char mv_to[MAX_BUFF];
    struct config_params_t *config_params;
    
    char* n __attribute__((unused));

    config_params = sr_config_get_param();

    if(!log_arr[curr].log_fp)
    {
		memset(current_file, 0, MAX_BUFF);
		sprintf(current_file,"%s%s%05d%s", prefix, buffer_TS, curr, postfix);
		log_arr[curr].log_fp = fopen(current_file, "a");

	}

    if(log_arr[curr].log_fp)
    {
        if( ftell( log_arr[curr].log_fp ) > MAX_LOG_SIZE )
		{
            fclose( log_arr[curr].log_fp );
            log_arr[curr].log_fp = 0;
            memset(mv_from, 0, MAX_BUFF);
            memset(mv_to, 0, MAX_BUFF);
          
			sprintf (mv_from, "%s%s%05d%s", config_params->temp_log_path, file_candidate, curr, postfix);	
			sprintf (mv_to, "%s%s%05d%s", config_params->log_path, file_candidate, curr, postfix);
     			
			if((sal_gets_space("/")< SAVE_SPACE))
			{
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
					"DISK SPACE TRESHOLD LIMIT REACHED %d -> CAN collector stopped\n",config_params->disk_space_treshold);
				sr_stop_task(SR_CAN_COLLECT_TASK);
			}
     		sal_rename(mv_from, mv_to);

            if(curr < FILE_QUEUE)
            {
				curr++;
				if (curr >= FILE_QUEUE)
					curr = 0;
			}
			
			memset(current_file, 0, MAX_BUFF);
			sprintf(current_file,"%s%s%05d%s", prefix ,buffer_TS,curr, postfix);	
            log_arr[curr].log_fp = fopen(current_file, "a");
		}
        fputs(str, log_arr[curr].log_fp);
        fflush(log_arr[curr].log_fp);
	}
}

SR_32 can_collector_init(void *data)
{
	struct config_params_t *config_params;

	int n __attribute__((unused));

	config_params = sr_config_get_param();

	if ((can_args.can_fd = init_can_socket(can_args.can_interface)) < 0) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
			"init_can_socket Failed\n");
		return SR_ERROR;
	}
	
	t = time(NULL);
	tm = *localtime(&t);
	
	n = snprintf(buffer_TS, 25, "%d_%02d_%02d___%02d_%02d_%02d___",tm.tm_year + 1900,tm.tm_mon + 1,tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec);
					
   	memset(file_candidate, 0, MAX_BUFF);
   	sprintf(prefix, "%s%s_",config_params->temp_log_path ,config_params->vin);
   	sprintf(file_candidate, "%s_%s",config_params->vin, buffer_TS);
   	
   	MAX_LOG_SIZE = 1024*1024*config_params->collector_file_size;
   	SAVE_SPACE = (config_params->disk_space_treshold/100.0)*(sal_gets_space("/"));
	
	can_collector_task(&can_args);
	
	return SR_SUCCESS;
}
