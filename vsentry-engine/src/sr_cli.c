/* sr_cli.c */
#include "sr_terminal.h"
#include "sr_conio.h"
#include "sr_config.h"
#include "sr_sal_common.h"

void start_cli(void)
{
	printf("%s%s", CLR_SCREEN, CSR_HOME);
	printf("+------------------------------------------------------------------------------+\n");
	while (1) {
		SR_8 input = getch();

		switch (input) {
			case 'b':
				printf ("\rb pressed");
				break;
			case 's':
				printf ("\rs pressed");
				break;
			case 't':
				printf ("\rt pressed");
				break;
		}
	}
}

