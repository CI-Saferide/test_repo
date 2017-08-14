#include "sr_sal_common.h"
#include "sr_msg.h"
#include "sr_msg_dispatch.h"
#include "sr_ec_common.h"


void sr_event_receiver(SR_8 *msg_buff, SR_U32 msg_len)
{
	struct sr_ec_new_connection_t *pNewConnection;
	SR_U32 offset = 0;

	while (offset < msg_len) {
		switch  (msg_buff[offset++]) {
			case SR_EC_NEW_CONNECTION:
				// collect
				pNewConnection = (struct sr_ec_new_connection_t *) &msg_buff[offset];
				// TODO: for now just temporary print. later hook to radix tree and other functionality
				printf("pid %d connected to %x(%d)\n", pNewConnection->pid, pNewConnection->remote_addr.v4addr, pNewConnection->dport);
				offset += sizeof(struct sr_ec_new_connection_t);
				break;
			default:
				break;
		}
	}
}
