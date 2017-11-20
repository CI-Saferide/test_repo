#include "sr_can_collector.h"
#include "sr_config_parse.h"

struct canTaskParams can_args = {.can_interface = DEFAULT_CAN0_INTERFACE, .can_print = SR_FALSE};

extern struct config_params_t config_params;

#define FILE_QUEUE 99999
const SR_8* disk = "/";
long long SAVE_SPACE;
long MAX_LOG_SIZE;


char prefix[256]; 			/* prefix of the file, including VIN */
char file_candidate[256]; 	/* filename of the current written log */ 
char postfix[] = "_.log";
int curr = 0;

struct candump_log log_arr[FILE_QUEUE];
char file1[256];

char buffer_TS[64];
time_t t;
struct tm tm;

void log_it(char* str)
{
    char mv_from[256];
    char mv_to[256];
    
    char* n __attribute__((unused));

    if(!log_arr[curr].log_fp)
    {
		memset(file1, 0, 256);
		sprintf(file1,"%s%s%05d%s", prefix, buffer_TS, curr, postfix);
		log_arr[curr].log_fp = fopen(file1, "a");
	}

    if(log_arr[curr].log_fp)
    {
        if( ftell( log_arr[curr].log_fp ) > MAX_LOG_SIZE )
		{
            fclose( log_arr[curr].log_fp );
            log_arr[curr].log_fp = 0;
            memset(mv_from, 0, 256);
            memset(mv_to, 0, 256);
          
			sprintf (mv_from, "%s%s%05d%s", config_params.temp_log_path, file_candidate, curr, postfix);	
			sprintf (mv_to, "%s%s%05d%s", config_params.log_path, file_candidate, curr, postfix);
     			
			if((sal_gets_space("/")< SAVE_SPACE))
			{
				sal_printf("DISK SPACE TRESHOLD LIMIT REACHED %d -> CAN collector stopped\n",config_params.disk_space_treshold);
				sr_stop_task(SR_CAN_COLLECT_TASK);
			}
     		rename(mv_from, mv_to);

            if(curr < FILE_QUEUE)
            {
				curr++;
				if (curr >= FILE_QUEUE)
					curr = 0;
			}
			
			memset(file1, 0, 256);
			sprintf(file1,"%s%s%05d%s", prefix ,buffer_TS,curr, postfix);	
            log_arr[curr].log_fp = fopen(file1, "a");
		}
        fputs(str, log_arr[curr].log_fp);
        fflush(log_arr[curr].log_fp);
	}
}

SR_32 can_collector_init(void *data)
{

	int n __attribute__((unused));

	if ((can_args.can_fd = init_can_socket(can_args.can_interface)) < 0) {
		sal_printf("init_can_socket Failed\n");
		return SR_ERROR;
	}
	
	t = time(NULL);
	tm = *localtime(&t);
	
	n = snprintf(buffer_TS, 25, "%d_%02d_%02d___%02d_%02d_%02d___",tm.tm_year + 1900,tm.tm_mon + 1,tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec);
					
   	memset(file_candidate, 0, 256);
   	sprintf(prefix, "%s%s_",config_params.temp_log_path ,config_params.vin);
   	sprintf(file_candidate, "%s_%s",config_params.vin, buffer_TS);
   	
   	MAX_LOG_SIZE = 1024*1024*config_params.collector_file_size;
   	SAVE_SPACE = (config_params.disk_space_treshold/100.0)*(sal_gets_space("/"));
	
	can_collector_task(&can_args);
	
	return SR_SUCCESS;
}
