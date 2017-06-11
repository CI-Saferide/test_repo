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

int main (int argc, char * argv[])
{
	FILE *fd;
	char buffer[1024];
	int CanCode=0;
	struct stat fstat_buf;
	int i=0,j=0, len=0;
	int skip = 0;
	int NumMessages = 0;
	struct timeval tv;

	gettimeofday(&tv, NULL);


	fd = fopen(COMMPORT, "r+");
	if (!fd) {
		printf ("Failed to open file\n");
		exit(-1);
	}
	printf("Com port successfully open\n");
	
	fprintf(fd, "atz\r\n");
	printf("Sent atz\n");
	len = fread(buffer, 1, 10, fd);
	printf("Read %d bytes:\n", len);
	for (i=0; i<len; i++) {
		if ((buffer[i] != '?') && (buffer[i] != '\n'))
			printf("%c", buffer[i]);
	}
	printf("**********\n");
	sleep(5);

	fprintf(fd, "stp31\n");
	printf("Sent stp31\n");
sleep (1);
	len = fread(buffer, 1, 1024, fd);
	printf("Read %d bytes:\n", len);
	for (i=0; i<len; i++) {
		printf("%c", buffer[i]);
	}
	printf("**********\n");

sleep (1);
	fprintf(fd, "ath1\r\n");
	printf("Sent ath1\n");
	len = fread(buffer, 1, 1024, fd);
	printf("Read %d bytes:\n", len);
	for (i=0; i<len; i++) {
		printf("%c", buffer[i]);
	}
	printf("**********\n");

sleep (1);
	fprintf(fd, "atd1\r\n");
	printf("Sent atd1\n");
	len = fread(buffer, 1, 1024, fd);
	printf("Read %d bytes:\n", len);
	for (i=0; i<len; i++) {
		printf("%c", buffer[i]);
	}
	printf("**********\n");

sleep (1);
	fprintf(fd, "stma\r\n");
	printf("Sent stma\n");
	len = fread(buffer, 1, 1024, fd);
	printf("Read %d bytes:\n", len);
	for (i=0; i<len; i++) {
		printf("%c", buffer[i]);
	}
	printf("**********\n");
	usleep(1000);
	len = fread(buffer, 1, 1024, fd);
	printf("Read %d bytes:\n", len);
	for (i=0; i<len; i++) {
		printf("%c", buffer[i]);
	}
	printf("**********\n");
	usleep(1000);
	len = fread(buffer, 1, 1024, fd);
	printf("Read %d bytes:\n", len);
	for (i=0; i<len; i++) {
		printf("%c", buffer[i]);
	}
	printf("**********\n");
	
	while(++j<5000){
	len = fread(buffer, 1, 10, fd);
	printf("Read %d bytes:\n", len);
	for (i=0; i<len; i++) {
		if ((buffer[i] != '?') && (buffer[i] != '\n'))
			printf("%c", buffer[i]);
	}
	printf("**********\n");
 	}




	fclose(fd);
	return 0;
	
}

