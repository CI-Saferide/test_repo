#include "sr_canbus_common.h"

SR_32 sr_can_tran_init(can_translator_t *can_traslator)
{
        memset(can_traslator->devices_map_to_can_id, -1, sizeof(can_traslator->devices_map_to_can_id));
        memset(can_traslator->special_devices_map_to_can_id, -1, 
			sizeof(can_traslator->special_devices_map_to_can_id));
        can_traslator->curr_can_dev_ind = 0;

        return SR_SUCCESS;
}

SR_BOOL is_special_interface(SR_U8 dev_id)
{
	return dev_id >= CAN_DEV_BASE;
}


SR_BOOL is_special_can_interface(char *interface) {
	if (!memcmp(interface, PCAN_DEV_NAME, strlen(PCAN_DEV_NAME)))
		return SR_TRUE;
	return SR_FALSE;
}

static void get_special_dev_name(SR_U8 if_id, SR_U8 dev_id, char *name, SR_U32 n) 
{
	switch (if_id) { 
		case PCAN_DEV:
			snprintf(name ,n, "%s%d", PCAN_DEV_NAME, dev_id);
			break;
		default:
			strcpy(name, "invalid");
			break;
	}
}

SR_32 sr_can_get_special_dev_id(char *name, SR_32 *if_id ,SR_32 *dev_id)
{
#ifndef _KERNEL
	if (!memcmp(name, PCAN_DEV_NAME, strlen(PCAN_DEV_NAME))) {
		*if_id = PCAN_DEV;
		*dev_id  = atoi(name + strlen(PCAN_DEV_NAME));
		return SR_SUCCESS;
        }
#endif

 	return SR_ERROR;
}

SR_32 sr_canbus_common_get_interface_name(SR_32 if_id, SR_32 dev_id, char *name, SR_U32 n)
{
	if (is_special_interface(if_id)) {
		get_special_dev_name(if_id, dev_id, name, n);
		return SR_SUCCESS;
	}
	return sal_get_interface_name(if_id, name, n);
}


SR_32 sr_can_tran_get_if_id(can_translator_t *can_traslator, SR_32 if_id, SR_32 dev_id, SR_32 *can_id)
{
	SR_32 rc, id;
	SR_32 *map_to_can;

	if (is_special_interface(if_id)) {
		map_to_can = can_traslator->special_devices_map_to_can_id;
		id = dev_id;
	} else {
		map_to_can = can_traslator->devices_map_to_can_id;
		id = if_id;
	}

        if (if_id >= MAX_DEVICE_NUMBER)
                return SR_ERROR;
        if (map_to_can[id] != -1) {
                *can_id = map_to_can[id];
                return SR_SUCCESS;
        }
        if (can_traslator->curr_can_dev_ind >= CAN_INTERFACES_MAX)
                return SR_ERROR;
        /* Create can dev translation */
        map_to_can[id] = can_traslator->curr_can_dev_ind;
        (can_traslator->curr_can_dev_ind)++;
        *can_id = map_to_can[id];

	if (is_special_interface(if_id)) {
		get_special_dev_name(if_id, dev_id, can_traslator->interfaces_name[*can_id], CAN_INTERFACES_NAME_SIZE);
	} else {
		rc = sal_get_interface_name(if_id, can_traslator->interfaces_name[*can_id], CAN_INTERFACES_NAME_SIZE);
		if (rc != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed getting interface name ",REASON);
			strcpy(can_traslator->interfaces_name[*can_id], "invalid");
		}
	}

        return SR_SUCCESS;
}

char *sr_can_tran_get_interface_name(can_translator_t *can_translator, SR_32 can_id)
{
        if (can_id >= can_translator->curr_can_dev_ind)
                return NULL;
        return can_translator->interfaces_name[can_id];
}
