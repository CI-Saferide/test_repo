#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_ring_buf.h"

unsigned char buf[8196];
unsigned char test_msg[17] = "1234567890abcdefg";

void *reader_thread(void *threadid)
{
    long tid;
	sr_ring_buffer *rb;
	unsigned char msg[512];
	int ret;

    tid = (long)threadid;
    printf("Hello World! It's me, thread #%ld!\n", tid);

	rb = (sr_ring_buffer *)threadid;
	printf("buf_size %d, read_ptr %d, write_ptr %d\n",
            rb->buf_size, rb->read_ptr, rb->write_ptr);

	while (1) {
		ret = read_buf(rb, msg, 17, 1);
		if (ret == 0) {
            sal_schedule_timeout(1);
			continue;
		}
		printf("read %d bytes ...\n", ret);
		if (memcmp(test_msg, msg, 17) != 0) {
			printf("bad msg: %s\n", msg);
			printf("buf_size %d, read_ptr %d, write_ptr %d\n",
				rb->buf_size, rb->read_ptr, rb->write_ptr);
			exit(-1);
		}	
	}
    pthread_exit(NULL);
}

int main (int argc, char *argv[])
{
    pthread_t threads;
    int rc, i,ret;
	sr_ring_buffer *rb = (sr_ring_buffer*)buf;

    printf("In main: creating thread\n");

	init_buf(8124, rb);

    rc = pthread_create(&threads, NULL, reader_thread, (void *)rb);
    if (rc){
       printf("ERROR; return code from pthread_create() is %d\n", rc);
       exit(-1);
    }

	//sleep(1);

	while (1) {
		i=0;
		while (i<400) {
			ret = write_to_buf(rb, test_msg, 17);
			i++;
		}
		usleep(1);
	}

    /* Last thing that main() should do */
    pthread_exit(NULL);
}
