#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <syscall.h>
#include <poll.h>

static void error(char *msg)
{
	perror(msg);
	exit(-1);
}

#define NUM_OF_THREADS 10
#define MAX_BUF 512
#define TEST_DEV_ADDR "192.168.1.17"

static void handle_data(int fd)
{
	fd_set rd_set;
	struct timeval tv = {};
	char buf[MAX_BUF], cmd[MAX_BUF], *address, *port, *user;
	int n;
	struct pollfd pfd[]={{fd,POLLIN,0}};

	tv.tv_sec = 5;
	
	while (1) { 
		poll(pfd, 1, 2000);
		if (!(pfd[0].revents & POLLIN))
			continue;
     		if ((n = recv(fd, buf, MAX_BUF, 0)) < 0)
			error("recv");
		if (!n) // socket is closed 
			break;
 		printf("Reieved %d bytes buf:%.*s \n", n, n, buf);
		if (!memcmp(buf, "IPERF_UDP", strlen("IPERF_UDP"))) {
			strtok(buf, ",");
			address = strtok(NULL, ",");
			port = strtok(NULL, ",");
			sprintf(cmd, "iperf -u -c %s -p%s -t1", address, port);
			printf("IPERF_UDP CMD:%s:\n", cmd);
			system(cmd);
		}
		if (!memcmp(buf, "SSH", strlen("SSH"))) {
			strtok(buf, ",");
			address = strtok(NULL, ",");
			user = strtok(NULL, ",");
			sprintf(cmd, "ssh -o ConnectTimeout=2 %s@%s", user, address);
			printf("SSH CMD:%s:\n", cmd);
			system(cmd);
		}
   	}
}

static void *handle_com(void *p)
{
  struct sockaddr_in ca = {};
  int fd = (int)p, newfd, calen = sizeof(ca), tid;
  char ip[20];

  tid = syscall(SYS_gettid);
  printf("Thread #:%d started \n", tid);
 
  while (1) { 
    if ((newfd = accept(fd, (struct sockaddr *)&ca, &calen)) < 0)
       error("accept");
    inet_ntop(AF_INET, &ca.sin_addr, ip, 20);
    printf("Accepted from %s \n", ip);
    handle_data(newfd);
  }

  return NULL;
}

void main(int argc, char **argv)
{
  int opt, n, fd, i;
  pthread_t ts[NUM_OF_THREADS];
  char ip[20];
  struct sockaddr_in sa = {};
  short port = 0;

  while ((opt = getopt(argc, argv, "p:")) != -1 ) {
       switch (opt) { 
          case 'p':
             port = atoi(optarg);
             break;
       }
  }

  if (!port) { 
     printf("usage: %s -p port\n", argv[0]);
     return;
  }

  sa.sin_addr.s_addr = INADDR_ANY;
  sa.sin_port = htons(port);
  sa.sin_family = AF_INET;
  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
     error("socket");
  if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)))
     error("connect");
  
  listen(fd, 5);  

  for (i = 0; i < NUM_OF_THREADS; i++)
      pthread_create(&ts[i], NULL, handle_com, (void *)fd);
  for (i = 0; i < NUM_OF_THREADS; i++)
      pthread_join(ts[0], NULL);
}
