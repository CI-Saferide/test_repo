//#include "sr_log.h" /* this file comes from kernel folder. mutual file between kernel and user space */
#include <stdio.h>
int main(int argc, char *argv[]){

	int err;
	
    sr_log_init("[VSENTRY]", 0);
	//sr_print(LOG_ERR, "failed to init ha_fpga %d %c %f", 10, 'e', 2.32);
	printf ("Welcome to sr-engine App! [PID: %d]\n",getpid());
	err = sr_net_init();
	if (err <0){
		printf ("ERROR: %d\n",err);
		return err;
	}

	while(1);
	return 0;
}
