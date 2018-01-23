#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "sysrepo_mng.h"
#define MAX_SIZE 100000

static int get_json_from_file(char *filename, char *buf, int size)
{
	FILE *fin;
	int n;

	if (!(fin = fopen(filename, "r"))) {
		printf("Failed opening file :%s \n", filename);
		return -1;
	}
	if ((n = fread(buf, 1, size, fin)) < 0) {
		printf("Failed reading file :%s \n", filename);
		return -1;
	}
	buf[n] = 0;

	fclose(fin);

	return 0;
}

int main(int argc, char **argv)
{
	sysrepo_mng_handler_t handler;
	int rc = 0, opt;
	char json_buf[MAX_SIZE + 1];

	json_buf[0] = 0;
	while ((opt = getopt(argc, argv, "f:s:")) != -1) {
		switch (opt) { 
			case 'f':
				get_json_from_file(optarg, json_buf, MAX_SIZE);
				break;
			case 's':
				strncpy(json_buf, optarg, MAX_SIZE);
				break;
			default:
				printf("Invalid option %c ignored \n", opt);
				break;
		}
	}

	if (!*json_buf) 
		return -1;

	if (sysrepo_mng_session_start(&handler)) {
		printf("sysrepo_mng_session_start failed \n");
		rc = -1;
		goto cleanup;
        }

	sysrepo_mng_parse_json(&handler, json_buf, NULL, 0);
	sleep(2);

cleanup:
	sysrepo_mng_session_end(&handler);

	return rc;
}
