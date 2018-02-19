#ifdef CONFIG_CAN_ML

#include "ml_can.h"
#include "sr_ml.h"
#include "sr_gen_hash.h"
#include "sal_mem.h"
#include "sr_control.h"
#include "sr_control.h"

static SR_BOOL	protect = SR_FALSE;

#define ML_CAN_HASH_SIZE 500
static struct sr_gen_hash *can_ml_hash;

SR_32 can_ml_comp(void *data_in_hash, void *comp_val)
{
	ml_can_item_t *ptr = (ml_can_item_t *)data_in_hash;

	if (ptr->msg_id == (SR_U32)(long int)comp_val)
		return 0;

	return 1;
}

static SR_U32 can_ml_create_key(void *data)
{
	SR_U32 msg_id = (SR_U32)(long int)data;

	if (!data)
		return 0;

	return msg_id;
}

void can_ml_print(void *data_in_hash)
{
	ml_can_item_t* ptr = (ml_can_item_t*)data_in_hash;
	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
					"can_ml msg_id: 0x%x, K = %d, h = %d", ptr->msg_id, ptr->K, ptr->h);
}

SR_32 sr_ml_can_hash_init(void)
{
	hash_ops_t can_ml_hash_ops = {};

	can_ml_hash_ops.create_key = can_ml_create_key;
	can_ml_hash_ops.comp = can_ml_comp;
	can_ml_hash_ops.print = can_ml_print;
	if (!(can_ml_hash = sr_gen_hash_new(ML_CAN_HASH_SIZE, can_ml_hash_ops, 0))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"failed to gen new hash table for can_ml enforce");
		return SR_ERROR;
	}

	return SR_SUCCESS;
}


void sr_ml_can_hash_deinit(void)
{
	sr_gen_hash_destroy(can_ml_hash);
}

static SR_32 sr_ml_can_hash_delete_all(void)
{
	return sr_gen_hash_delete_all(can_ml_hash);
}


static SR_BOOL rate_limit(ml_can_item_t* item)
{
	struct config_params_t *config_params;
	
	config_params = sr_control_config_params();
	/* check if we are in disable state */
	/* we need the info to the algorithm even when the state is disbled */
	if(SR_FALSE == vsentry_get_state())
		return (SR_FALSE);
	
	if ((item->ts - item->last_cef_ts) < 1000000) {
		if (item->cef_msg_cnt < (config_params->cef_max_rate-1)) {
			item->cef_msg_cnt++;
			return (SR_TRUE);
		}
	} else {
		item->cef_msg_cnt = 0;
		item->last_cef_ts = item->ts;
		return (SR_TRUE);
	}
	return (SR_FALSE);
}

static SR_BOOL can_ml_test(ml_can_item_t* item)
{
	SR_32			tmp_calc;
	
	tmp_calc = item->calc_sigma_plus + item->delta - item->mean_delta - item->K;
	item->calc_sigma_plus = (tmp_calc > 0)? tmp_calc : 0;
	
	tmp_calc = item->calc_sigma_minus - item->delta + item->mean_delta - item->K;
	item->calc_sigma_minus = (tmp_calc > 0)? tmp_calc : 0;
	
	if (item->calc_sigma_plus > item->h) {
		item->calc_sigma_plus = 0;
		item->calc_sigma_minus = 0;

		if (rate_limit(item) == SR_TRUE)
			CEF_log_event(SR_CEF_CID_ML_CAN, "CAN msg dropped", SEVERITY_HIGH,
							"msg 0x%x dropped by learning machine, IAT too high", item->msg_id);
		return SR_ML_DROP;
	} else if (item->calc_sigma_minus > item->h) {
		item->calc_sigma_plus = 0;
		item->calc_sigma_minus = 0;
		if (rate_limit(item) == SR_TRUE)
			CEF_log_event(SR_CEF_CID_ML_CAN, "CAN msg dropped", SEVERITY_HIGH,
							"msg 0x%x dropped by learning machine, IAT too low", item->msg_id);
		return SR_ML_DROP;
	}
	return SR_ML_ALLOW;
}

static SR_32 update_can_item(disp_info_t* info, struct sr_ml_can_msg *msg)
{
	ml_can_item_t 	*can_ml_item;
	SR_U8			index;

	if (!(can_ml_item = sr_gen_hash_get(can_ml_hash, (void *)(long)info->can_info.msg_id))) {
			/* new mid, allocate new buffer */
			SR_Zalloc(can_ml_item, ml_can_item_t *, sizeof(ml_can_item_t));
			if (!can_ml_item) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
								"failed to allocate buffer for can_ml enforce table (msg_id 0x%x)", info->can_info.msg_id);
				/* we cannot decide about this msg, so we allow it */
				return SR_ML_ALLOW;
			}
			can_ml_item->msg_id = info->can_info.msg_id;
			can_ml_item->ts = 0;
			can_ml_item->calc_sigma_plus = 0;
			can_ml_item->calc_sigma_minus = 0;
			can_ml_item->K = 0;
			can_ml_item->last_cef_ts = 0;
			if (msg != NULL) {
				/* we have learning data from user space, let's update it */
				can_ml_item->K = msg->K;
				can_ml_item->h = msg->h;
				can_ml_item->mean_delta = msg->mean_delta;
			}
			if ((sr_gen_hash_insert(can_ml_hash, (void *)(long)info->can_info.msg_id , can_ml_item)) != SR_SUCCESS) {
					CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
									"failed to insert mid 0x%x to can_ml enforce table", can_ml_item->msg_id);
					/* we cannot decide about this msg, so we allow it */
					return SR_ML_ALLOW;
			}
	} else {
		/* mid exist, update the data */
		//TOOD: handle wrap arround cases
		if (can_ml_item->ts) {
			/* we have ts, so we can decide about this packet */
			can_ml_item->delta = info->can_info.ts - can_ml_item->ts;
			can_ml_item->ts = info->can_info.ts;
			for (index=0; index<8; index++)
				can_ml_item->payload[index] = info->can_info.payload[index];
			if ((can_ml_item->h) && (protect == SR_TRUE))
				return(can_ml_test(can_ml_item));
		} else {
			/* this is the second message, but the first "real" one */
			/* (previous message came from the user space as learning info) */
			can_ml_item->ts = info->can_info.ts;
		}
	}
	/* we don't have learning data yet, cannot decide about this msg */
	return SR_ML_ALLOW;
}

SR_U8 test_can_msg(disp_info_t* info)
{
	if (protect == SR_TRUE) {
		return (update_can_item(info, NULL));
	}
	else {
		return SR_ML_ALLOW;
	}
}

SR_32 sr_ml_can_handle_message(struct sr_ml_can_msg *msg)
{
	disp_info_t info;
	
	if (msg->msg_id == CAN_ML_START_PROTECT) {
		/* this is an indication for start the protection */
		protect = SR_TRUE;
		CEF_log_event(SR_CEF_CID_ML_CAN, "info", SEVERITY_LOW,
						"can_ml protection started");
	} else if (msg->msg_id == CAN_ML_STOP_PROTECT) {
		/* this is an indication for protection stop */
		if (protect == SR_TRUE) {
			CEF_log_event(SR_CEF_CID_ML_CAN, "info", SEVERITY_LOW,
						"can_ml protection stopped");
		}
		protect = SR_FALSE;
		sr_ml_can_hash_delete_all();
	} else {
		info.can_info.ts = 0;
		info.can_info.msg_id = msg->msg_id;
		update_can_item(&info, msg);
	}
	return SR_SUCCESS;
}

SR_BOOL get_can_ml_state(void)
{
	return (protect);
}

#endif /* CONFIG_CAN_ML */
