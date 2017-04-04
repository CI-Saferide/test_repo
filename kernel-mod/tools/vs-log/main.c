#include "include/sr_log.h"

int main(int argc, char *argv[]){

	int err;
	
    sr_log_init("sr-test", 0);
	//sr_print(LOG_ERR, "failed to init ha_fpga %d %c %f", 10, 'e', 2.32);
	
	err = sr_net_init();
	
	return err;
}
