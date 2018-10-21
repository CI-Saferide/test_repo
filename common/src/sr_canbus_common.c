#include "sr_canbus_common.h"

SR_32 sr_can_tran_init(can_translator_t *can_traslator)
{
        memset(can_traslator->devices_map_to_can_id, -1, sizeof(can_traslator->devices_map_to_can_id));
        can_traslator->curr_can_dev_ind = 0;

        return SR_SUCCESS;
}

SR_32 sr_can_tran_get_if_id(can_translator_t *can_traslator, SR_U8 dev_id, SR_U8 *can_id)
{
        char *if_name;

        if (dev_id >= MAX_DEVICE_NUMBER)
                return SR_ERROR;
        if (can_traslator->devices_map_to_can_id[dev_id] != (SR_8)-1) {
                *can_id = can_traslator->devices_map_to_can_id[dev_id];
                return SR_SUCCESS;
        }
        if (can_traslator->curr_can_dev_ind >= CAN_INTERFACES_MAX)
                return SR_ERROR;
        /* Create can dev translation */
        can_traslator->devices_map_to_can_id[dev_id] = can_traslator->curr_can_dev_ind;
        *can_id = can_traslator->curr_can_dev_ind;
        if ((if_name = sal_get_interface_name(dev_id))) {
                strncpy(can_traslator->interfaces_name[can_traslator->curr_can_dev_ind], if_name, CAN_INTERFACES_NAME_SIZE);
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
