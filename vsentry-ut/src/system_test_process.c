#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <signal.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int count;
static int sleep_time = 100000;
static int loop_count = 100000000;
static int loop2 = 1;
static int sync1, sync2;

static void *func(void *p)
{
	int is_even = (int)(long)p, i, j;
	int pcount = 0;

	while (1) {
		pthread_mutex_lock(&mutex);
		while ((is_even && (count & 1)) || (!is_even && !(count & 1))) 
			pthread_cond_wait(&cond, &mutex);
		pcount++;
		if (0 && pcount % 10 == 0) {
			printf("XZXZXXXXXXXXXXXXXXX %s count:%d lc:%d \n", is_even ? "E" :"O", count, loop_count);
		}
		count++;
		for (i = 0; i < loop_count; i++);
			for (j = 0; j < loop_count; j++);
		pthread_cond_signal(&cond);
		pthread_mutex_unlock(&mutex);
		usleep(sleep_time);
	}
	
	return NULL;
}

static void *func2(void *p)
{
	int i, j;

	while (loop2) {
		for (i = 0; i < loop_count; i++);
			for (j = 0; j < loop_count; j++);
	}

	return NULL;
}

static void handler(int signal)
{
	switch (signal) {
		case 11:
			if (!sync1)
				sync1 = 1;
			else
				sync2 = 1;
			break;
		default:
			break;
	}
}

int main(void)
{
	pthread_t teven, todd;
	FILE *f1, *f2;
	char buf[10000];
	int i;
	pthread_t ts[3];

	signal(11, handler);

	printf("%d\n", getpid());
	pthread_create(&teven, NULL, func, (void *)1);
	pthread_create(&todd, NULL, func, (void *)0);

	if (!(f1 = fopen("stam1.txt", "w")))
		perror("fopen");
	fwrite(buf, 1, 700, f1);
	fflush(f1);

	if (!(f2 = fopen("stam2.txt", "w")))
		perror("fopen");

	while (!sync1)
		sleep(1);

	for (i = 0; i < 3; i++)
		pthread_create(&ts[i], NULL, func2, NULL);

	while (!sync2)
		sleep(1);
	loop2 = 0;

	for (i = 0; i < 3; i++)
		pthread_cancel(ts[i]);

	pthread_join(teven, NULL);
	pthread_join(todd, NULL);

	return 0;
}
