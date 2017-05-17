/* file: msg_process.c
 * purpose: this file implements the process function of the
 * 			messages comes from the main socket (from the user sapce engine application)
*/
#include "multiplexer.h"
#include "sal_linux.h" //for sal_kernel_print_info

void main_socket_process_cb(void *data)
{
    /* do stuff and things with the event */
    sal_kernel_print_info("TESTING_CALLBACK: %s",(char*)data);   
}
