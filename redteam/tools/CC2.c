#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#define COMMPORT "/dev/rfcomm0"

typedef enum {
	STATE_CODE1 = 1,
	STATE_CODE2,
	STATE_CODE3,
	STATE_POST_CODE_SPACE,
	STATE_MSGLEN,
	STATE_MSGDATA,
	STATE_BUFFERFULL,
	STATE_INVALID
} state_machine;

int main (int argc, char * argv[])
{
	int fd;
	char buffer[10240];
	int i=0,j=0, len=0, retval;
	struct timeval tv;
	fd_set in_fds;
	struct timeval timeout;
	int state = STATE_CODE1;

	gettimeofday(&tv, NULL);


	fd = open(COMMPORT, O_RDWR);
	if (fd<0) {
		printf ("Failed to open file\n");
		exit(-1);
	}
	printf("Com port successfully open\n");
	
	write(fd, "atz\n", 4);
	printf("Sent atz\n");
	sleep(5);
	while (1) {
		len = read(fd, buffer, 10);
		for (i=0; i<len; i++) {
			if ((buffer[i] != '?') && (buffer[i] != '\n'))
				printf("%c", buffer[i]);
		}
		if (len <10) break;
	}

	sleep(1);	
	write (fd, "stp31\r\n",7);
	sleep(1);	
	write (fd, "ath1\r\n",6);
	sleep(1);	
	write (fd, "atd1\r\n",6);
	sleep(1);	
	write (fd, "stma\r\n", 6);
	printf("Starting to record CAN messages\n");
	sleep(1);	
	
	while(1){
		int retcode, msglen, nodata=0;

		timeout.tv_sec=1;
		timeout.tv_usec=0;
		FD_ZERO(&in_fds);
		FD_SET(fd, &in_fds);
		retval = select(fd+1, &in_fds, NULL, NULL, &timeout);
		if (retval == 1) { // read some messages
			nodata = 0;
			len = read(fd, buffer, 10240);
//			printf("Read %d bytes:\n", len);
			i=0;
			while (i<len) {
				switch (state) {
					case STATE_CODE1:
							if ((buffer[i] >= '0') && (buffer[i] <= '4')) { // start of a code
								if (i+3 > len) {
									printf("Message ended mid-buffer\n");
									break;
								}
								if (buffer[i+3] != ' ') {
									printf("data is not a CAN code:\n");
									for (j=-5; j<15; j++) {
										printf("%c(%x)", buffer[i+j], buffer[i+j]);
									}
									printf("\n");
									break;
								}
								if (sscanf(&buffer[i], "%x %d", &retcode, &msglen) != 2) {
									printf("Failed to read code and length:\n");
									for (j=0; j<15; j++) {
										printf("%c(%x)", buffer[i+j], buffer[i+j]);
									}
									break;
								}
								if ((msglen<=0) || (msglen>8)) {
									printf("Error parsing message length (%d)\n", msglen);
									for (j=0; j<15; j++) {
										printf("%c(%x)", buffer[i+j], buffer[i+j]);
									}
									break;
								}
								i+=6;
								if ((i+(msglen*3)) < len) {
									gettimeofday(&tv, NULL);
									printf ("###%lu:%lu %3x %d ", tv.tv_sec, tv.tv_usec, retcode, msglen);
									for (j=0; j<(msglen*3-1); j++) {
										printf("%c", buffer[i+j]);
									}
									printf("###\r\n");
									//printf("Message ended with a %x char\n", buffer[j]);
									i+=(j-1);
								} else {
									// Read partial message...
									gettimeofday(&tv, NULL);
									msglen = (msglen*3) - (len-i);
									state = STATE_MSGDATA;
									printf ("$$$%lu:%lu %x %d ", tv.tv_sec, tv.tv_usec, retcode, msglen);
									for (; i<len; i++) {
										printf("%c", buffer[i]);
									}
								}
							}
						break;
					case STATE_CODE2:
						break;
					case STATE_CODE3:
						break;
					case STATE_POST_CODE_SPACE:
						break;
					case STATE_MSGLEN:
						break;
					case STATE_MSGDATA:
//						printf("Got data in data state, expecting %d, got %d\n", msglen, len);
						if (len >= msglen) {
							for (;i<msglen;i++) {
								printf("%c", buffer[i]);
							}
							printf("$$$\r\n");
							state = STATE_CODE1;
						} else {
							for (i=0;i<len;i++,msglen--) {
								printf("%c", buffer[i]);
							}
						}
						break;
					case STATE_BUFFERFULL:
						break;
					case STATE_INVALID:
						break;
				}
				i++;
			}
			//for (i=0; i<len; i++) {
			//	printf("%c", buffer[i]);
			//}
		} else if (retval == 0) {
			write (fd, "\r\n",2);
			if (++nodata > 10) {
				printf("No data for 10 seconds, dropping\n");
				break;
			}
		} else {
			perror("select");
			break;
		}
	}




	close(fd);
	return 0;
	
}

