#include "sr_sal_common.h"
#include "sr_msg.h"
#include "sr_msg_dispatch.h"
#include "sr_ec_common.h"
#include "sr_ml_conngraph.h"
#include "sr_event_receiver.h"
#include "sr_cls_rules_control.h"
#include "sr_cls_file_control.h"

SR_32 sr_ml_mode = ML_MODE_LEARN;
// TODO: load profile at startup, determine default loading state

void sr_ml_changemode(SR_32 mode)
{
	if (mode != sr_ml_mode) {
		switch (mode) {
			case ML_MODE_LEARN:
				// clear runtime data structure, start new learning
				sr_ml_conngraph_clear_graph();
				//sr_ml_conngraph_loadconf();
				break;
			case ML_MODE_DETECT:
				// TODO: load learnt profile?
				sr_ml_conngraph_save();
				break;
		}
		sr_ml_mode = mode;
	}
	
}

int counter=0;

void sr_event_receiver(SR_8 *msg_buff, SR_U32 msg_len)
{
	struct sr_ec_new_connection_t *pNewConnection;
	struct sr_ec_file_t *pNewFile;
	SR_U32 offset = 0, rc;

	while (offset < msg_len) {
		switch  (msg_buff[offset++]) {
			case SR_EVENT_NEW_CONNECTION:
				// collect
				pNewConnection = (struct sr_ec_new_connection_t *) &msg_buff[offset];
				sr_ml_conngraph_event(pNewConnection);
				offset += sizeof(struct sr_ec_new_connection_t);
				break;
			case SR_EVENT_FILE_CREATED:
				pNewFile = (struct sr_ec_file_t *) &msg_buff[offset];
				offset += sizeof(struct sr_ec_file_t);
				if ((rc = sr_cls_file_create((char *)(pNewFile->name))) != SR_SUCCESS) {
					sal_printf("Error %s: handle_file_created, failed file:%s\n", __FUNCTION__, pNewFile->name);
				}
				break;
			default:
				break;
		}
	}
}
