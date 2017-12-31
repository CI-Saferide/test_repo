#ifdef CONFIG_CAN_ML

#include <stdio.h>
#include "sr_ml_can.h"
#include "sr_gen_hash.h"
#include <sr_sal_common.h>
#include <sal_mem.h>
#include "sr_msg.h"
#include "sr_msg_dispatch.h"
#include "sr_ml_can_common.h"

static SR_BOOL 	learning = 1;	

#define ML_CAN_HASH_SIZE 500
static struct sr_gen_hash *can_ml_hash;

SR_32 can_ml_comp(void *data_in_hash, void *comp_val)
{
	ml_can_item_t *ml_can_item = (ml_can_item_t *)data_in_hash;

	if (ml_can_item->msg_id == (SR_U32)(long int)comp_val)
		return 0;

	return 1;
}

void can_ml_print(void *data_in_hash)
{
	ml_can_item_t* ptr = (ml_can_item_t*)data_in_hash;
	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
					"can_ml msg_id: 0x%x, sigma_plus = %d, sigma_minus = %d, K = %d, h = %d", ptr->msg_id, ptr->calc_sigma_plus, ptr->calc_sigma_plus, ptr->K, ptr->h);
}

static SR_U32 can_ml_create_key(void *data)
{
	SR_U32 msg_id = (SR_U32)(long int)data;

	if (!data)
		return 0;

	return msg_id;
}


SR_32 sr_ml_can_hash_init(void)
{
	hash_ops_t can_ml_hash_ops = {};

	can_ml_hash_ops.create_key = can_ml_create_key;
	can_ml_hash_ops.comp = can_ml_comp;
	can_ml_hash_ops.print = can_ml_print;
	if (!(can_ml_hash = sr_gen_hash_new(ML_CAN_HASH_SIZE, can_ml_hash_ops))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"failed to gen new hash table for can_ml");
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

void sr_ml_can_print_hash(void)
{
	sr_gen_hash_print(can_ml_hash);
}

void sr_ml_can_hash_deinit(void)
{
	sr_gen_hash_destroy(can_ml_hash);
}

SR_32 r_ml_can_hash_delete_all(void)
{
	return sr_gen_hash_delete_all(can_ml_hash);
}

static SR_U32 calc_h (SR_U32 K)
{
	return (2 * K);
}

static SR_32 calc_learn_values(void *hash_data, void *data)
{
	ml_can_item_t* ptr = (ml_can_item_t*)hash_data;
	sr_ml_can_msg_t *msg;

	ptr->mean_delta = (SR_U32)((ptr->sum_delta) / (ptr->samples));
	ptr->K = (SR_U32)(ptr->mean_delta / 4);
	ptr->h = calc_h(ptr->K);
	msg = (sr_ml_can_msg_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
	if (msg) {
		msg->msg_type = SR_MSG_TYPE_ML_CAN;
		msg->sub_msg.msg_id = ptr->msg_id;
		msg->sub_msg.K = ptr->K;
		msg->sub_msg.h = ptr->h;
		msg->sub_msg.mean_delta = ptr->mean_delta;
		sr_send_msg(ENG2MOD_BUF, sizeof(msg));
	} else {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"failed to transfer can_ml leaning info for msg_id 0x%x", ptr->msg_id);
	}
	ptr->calc_sigma_plus = 0;
	ptr->calc_sigma_minus = 0;
	return SR_SUCCESS;
}

static SR_32 update_can_item(SR_U64 ts, SR_U32 msg_id)
{
	ml_can_item_t 	*can_ml_item;
	SR_32 			rc;
	SR_U64			tmp_delta;
	sr_ml_can_msg_t *msg;

	if (!(can_ml_item = sr_gen_hash_get(can_ml_hash, (void *)(long)msg_id))) {
			/* new mid, allocate new buffer */
			SR_Zalloc(can_ml_item, ml_can_item_t *, sizeof(ml_can_item_t));
			if (!can_ml_item)
					return SR_ERROR;
			can_ml_item->msg_id = msg_id;
			can_ml_item->ts = ts;
			can_ml_item->calc_sigma_plus = 0;
			can_ml_item->calc_sigma_minus = 0;
			can_ml_item->K = 0;
			can_ml_item->sum_delta = 0;
			can_ml_item->samples = 0;
			if ((rc = sr_gen_hash_insert(can_ml_hash, (void *)(long)msg_id , can_ml_item)) != SR_SUCCESS) {
					CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
									"failed to insert mid 0x%x to can_ml table", msg_id);
					return SR_ERROR;
			}
	} else {
		/* mid exist, update the data */
		if (can_ml_item->delta != 0) {
			//TOOD: handle wrap arround cases;
			tmp_delta = (ts - can_ml_item->ts);
			can_ml_item->d_delta = tmp_delta - can_ml_item->delta;
			can_ml_item->delta = tmp_delta;
			can_ml_item->ts = ts;
			if (learning) {
				can_ml_item->sum_delta+= can_ml_item->delta;
				can_ml_item->samples++;
				if (ts  > LEARNING_TIME) {
					learning = 0;
					sr_gen_hash_exec_for_each(can_ml_hash, calc_learn_values, NULL);
					/* update the kernel that all the learning data transfered */
					msg = (sr_ml_can_msg_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
					if (msg) {
						msg->msg_type = SR_MSG_TYPE_ML_CAN;
						msg->sub_msg.msg_id = 0xffffffff;
						sr_send_msg(ENG2MOD_BUF, sizeof(msg));
					} else {
						CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
									"failed to transfer can_ml leaning info");
					}
				}
			}
		} else {
			/* this os the second packet, no delta yet */
			can_ml_item->delta = ts - can_ml_item->ts;
			can_ml_item->ts = ts;
			if (learning) {
				can_ml_item->sum_delta+= can_ml_item->delta;
				can_ml_item->samples++;
			}
		}
	}
	return SR_SUCCESS;
}

void ml_can_get_raw_data(SR_U64 ts, SR_U32 msg_id)
{
	update_can_item(ts, msg_id);
}

#endif /* CONFIG_CAN_ML */
