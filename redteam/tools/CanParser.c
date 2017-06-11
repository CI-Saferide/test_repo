#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

struct rep {
	struct rep *next;
	int index;
};

struct CanMsg {
	struct CanMsg *next, *prev;
	struct rep *reps;
//	int Code;
	int len;
	int count;
};

struct CanMsg Messages[2048];

void AddRep(struct rep *reps, int index) {
	while (reps->next)
		reps = reps->next;
	reps->next = calloc(sizeof(struct rep),1);
	if (!reps->next) {
		printf("Error: Failed to alloc reps\n");
		exit(-5);
	}
	reps->next->index = index;
}

void LogMsg(int Code, int len, int index) {
	struct CanMsg *MsgIter, *msg;
	struct rep *rep;

	if ((Messages[Code].len) && (len != Messages[Code].len)) {
		printf("NOTE: Code %x has variable length: %d and %d\n", Code, len, Messages[Code].len);
	}
	Messages[Code].count++;
	Messages[Code].len = len;
	if (!Messages[Code].reps) {
		Messages[Code].reps = calloc(sizeof(struct rep),1);
		if (!Messages[Code].reps) {
			printf("Error: Failed to alloc reps\n");
			exit(-5);
		}
		Messages[Code].reps->index = index;
		return;
	}
	rep = calloc(sizeof(struct rep),1);
	if (!rep) {
		printf("Error: Failed to alloc reps\n");
		exit(-5);
	}
	rep->index = index;
	rep->next = Messages[Code].reps;
	Messages[Code].reps = rep;

	return;
}
		
void DumpMessages() {
	int i,j=0;
	struct rep *rep;
	for (i=0; i<2048; i++) {
		if (Messages[i].count) {
			printf("Message Code %x repeated %d times, length is %d\n", i, Messages[i].count, Messages[i].len);
/*
			printf("Last 10 times are on indexes ");
			rep = Messages[i].reps;
			for (j=0; j<10; j++) {
				printf("%d ", rep->index);
				rep = rep->next;
			}
			printf("\n");
*/
		}
	}
}

int main (int argc, char * argv[])
{
	int fd;
	char *buffer;
	int CanCode=0;
	struct stat fstat_buf;
	int i=0,j=0, len=0;
	int skip = 0;
	int NumMessages = 0;

	memset(Messages, 0, sizeof(Messages));
	if (argc != 2) {
		printf ("USAGE: %s <filename>\n", argv[0]);
		exit (-1);
	}
	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		printf ("fd is %d\n", fd);
		exit(-1);
	}
	if (fstat(fd, &fstat_buf)) {
		printf ("Failed to stat file\n");
		exit (-1);
	}
	buffer = malloc(fstat_buf.st_size);
	if (!buffer) {
		printf("ERROR: failed to allocate buffer\n");
		exit (-1);
	}
	if (read(fd, buffer, fstat_buf.st_size) != fstat_buf.st_size) {
		printf("Failed to read file\n");
		exit(-2);
	}
	printf ("File read, start parsing\n");
	
	while(i<fstat_buf.st_size) {
		j=i;
		while((j<fstat_buf.st_size) && (!isspace(buffer[j])))
			j++;
		if ((j-i) == 3) {
			sscanf(&buffer[i], "%x", &CanCode);
			sscanf(&buffer[i+3], "%x", &len);
			LogMsg(CanCode, len, ++NumMessages);
			printf("\r%d", NumMessages);
			//printf("Message Code: %x Length %d\n", CanCode, len);
		}
		i = j+1;
		while(isspace(buffer[i]))
			i++;
	}
	printf("\n");
	
	
	DumpMessages();


	close(fd);
	return 0;
	
}

