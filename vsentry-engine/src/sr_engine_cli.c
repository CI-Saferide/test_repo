#include "sr_types.h"
#include "sr_engine_cli.h"
#include "sr_db.h"
#include "sr_db_file.h"
#include "sr_db_ip.h"
#include "sr_db_can.h"
#include "sal_linux.h"

void sr_engine_cli_load(SR_32 fd)
{
	char buf[2] = {};

	action_dump(fd);
	file_rule_dump_rules(fd);
	ip_rule_dump_rules(fd);
	can_rule_dump_rules(fd);
	buf[0] = SR_CLI_END_OF_TRANSACTION;
	if (write(fd, buf, 1) < 1) {
		printf("write failed buf\n");
	}
}

void sr_engine_cli_commit(SR_32 fd)
{
        SR_U32 len, ind;
        char cval, buf[10000], syncbuf[2] = {};

        // Snc 
	syncbuf[0] = SR_CLI_END_OF_TRANSACTION;
	if (write(fd, syncbuf, 1) < 1) {
		printf("Failed writing sync buf\n");
		return;
	}

        buf[0] = 0;
        ind = 0;
        for (;;) {
                len = read(fd, &cval, 1);
                if (!len) {
                        printf("Failed reading from socket");
                        return;
                }
                switch (cval) {
                        case SR_CLI_END_OF_TRANSACTION: /* Finish commit */
                                goto out;
                        case SR_CLI_END_OF_ENTITY: /* Finish entity */
                                buf[ind] = 0;
                                printf("Got buffer:%s: \n", buf);
                                buf[0] = 0;
                                ind = 0;
                                break;
                        default:
                                buf[ind++] = cval;
                                break;
                }
        }

out:
        return;
}


