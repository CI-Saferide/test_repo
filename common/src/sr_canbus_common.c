#include "sr_canbus_common.h"

SR_32 sr_can_tran_init(can_translator_t *can_traslator)
{
        memset(can_traslator->devices_map_to_can_id, -1, sizeof(can_traslator->devices_map_to_can_id));
        can_traslator->curr_can_dev_ind = 0;

        return SR_SUCCESS;
}

SR_BOOL is_special_interface(SR_U8 dev_id)
{
	return dev_id >= CAN_DEV_BASE;
}

static void get_special_dev_name(SR_U8 dev_id, char *name) 
{
	switch (dev_id) { 
		case PCAN_DEV:
			strcpy(name, PCAN_DEV_NAME);
			break;
		default:
			strcpy(name, "invalid");
			break;
	}
}

SR_32 sr_can_get_special_dev_id(char *name, SR_U32 *dev_id)
{
	if (!strcmp(name, PCAN_DEV_NAME)) {
		*dev_id = PCAN_DEV;
		return SR_SUCCESS;
        }

 	return SR_ERROR;
}

SR_32 sr_can_tran_get_if_id(can_translator_t *can_traslator, SR_U8 dev_id, SR_U8 *can_id)
{
	SR_32 rc;

        if (dev_id >= MAX_DEVICE_NUMBER)
                return SR_ERROR;
        if (can_traslator->devices_map_to_can_id[dev_id] != -1) {
                *can_id = can_traslator->devices_map_to_can_id[dev_id];
                return SR_SUCCESS;
        }
        if (can_traslator->curr_can_dev_ind >= CAN_INTERFACES_MAX)
                return SR_ERROR;
        /* Create can dev translation */
        can_traslator->devices_map_to_can_id[dev_id] = can_traslator->curr_can_dev_ind;
        *can_id = can_traslator->curr_can_dev_ind;
	if (is_special_interface(dev_id)) {
		get_special_dev_name(dev_id, can_traslator->interfaces_name[can_traslator->curr_can_dev_ind]);
	} else {
		rc = sal_get_interface_name(dev_id, can_traslator->interfaces_name[can_traslator->curr_can_dev_ind]);
		if (rc != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed getting interface name ",REASON);
			strcpy(can_traslator->interfaces_name[can_traslator->curr_can_dev_ind], "invalid");
		}
	}
        (can_traslator->curr_can_dev_ind)++;

        return SR_SUCCESS;
}

char *sr_can_tran_get_interface_name(can_translator_t *can_translator, SR_32 if_id)
{
        if (if_id >= CAN_INTERFACES_MAX)
                return NULL;
        return can_translator->interfaces_name[if_id];
}
