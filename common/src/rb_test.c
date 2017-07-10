#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_sal_common.h"
#include "sr_ring_buf.h"

#define MEM_SIZE		0x4000
#define NUM_OF_BUFFERS 	0x70
#define BUFFER_SIZE 	0x80

unsigned char buf[MEM_SIZE];
unsigned char run = 1;

void *reader_thread(void *threadid)
{
	long tid;
	sr_ring_buffer *rb;
	unsigned char *msg, data = '0';
	int ret;

	tid = (long)threadid;
	printf("Hello World! It's me, thread #%ld!\n", tid);

	rb = (sr_ring_buffer *)threadid;

	while (1) {
		msg = sr_read_buf(rb, &ret);
		if (!msg) {
			if (!run)
				break;
			usleep(rand()%100);
			continue;
		}
		//printf("read %02d bytes ... %s\n", ret, msg);
		if (data != *msg) {
			printf("ERROR expected %c got %s\n", data, msg);
			exit (-1);
		}
		data++;
		if (data > '9')
			data = '0';
		sr_free_buf(rb);
	}
	printf("reader_thread EXIT\n");
	pthread_exit(NULL);
}

int main (int argc, char *argv[])
{
	pthread_t threads;
	int rc, ret;
	sr_ring_buffer *rb = (sr_ring_buffer*)buf;
	SR_U8 *ptr;
	SR_8 data= '0';
	SR_32 itr = 10000;

	ret = sr_init_ring_buf((void*)buf, MEM_SIZE, NUM_OF_BUFFERS, BUFFER_SIZE);
	if (ret == 0 ) {
		printf("sr_init_ring_buf failed\n");
		exit(-1);
	}

	printf("In main: creating thread\n");
	rc = pthread_create(&threads, NULL, reader_thread, (void *)rb);
	if (rc){
	   printf("ERROR; return code from pthread_create() is %d\n", rc);
	   exit(-1);
	}

	while (itr > 0) {
		SR_32 i=0;
		SR_32 j = rand()% (2 * NUM_OF_BUFFERS);
	
		while ( i<j ) {
			SR_32 len = (rand()% BUFFER_SIZE );

			if (len == 0)
				len = 1;

			ptr = sr_get_buf(rb, len + 1);
			if (ptr) {
				//sal_printf("Writing %c size %d\n", data, len);
				memset(ptr, data, len);
				*(ptr + len + 1) = 0;
				sr_write_buf(rb, len + 1);
				i++;
				data++;
				if (data > '9')
					data = '0';
			}
			else
				usleep(rand()%100);
		}
		itr--;
	}

	run = 0;

	sleep(1);

	sr_print_rb_info(rb);

	return 0;
}
