#ifdef CONFIG_CAN_ML

#include <stdio.h>
#include "sr_ml_can.h"
#include "sr_gen_hash.h"
#include <sr_sal_common.h>
#include <sal_mem.h>

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

static SR_32 calc_K_factors(void *hash_data, void *data)
{
	//SR_U32	dt_mean;
	ml_can_item_t* ptr = (ml_can_item_t*)hash_data;
	ptr->mean_delta = (SR_U32)((ptr->sum_delta) / (ptr->samples));
	ptr->K = (ptr->mean_delta / 2);
	ptr->h = calc_h(ptr->K);
	if ((ptr->msg_id == 0x5a0) || (ptr->msg_id == 0x1a0) || (ptr->msg_id == 0x280))
		printf("msg_id 0x%x: samples = %d, sum_delta = %d, mean = %d, K= %d, h= %d\n", ptr->msg_id, ptr->samples, ptr->sum_delta, ptr->mean_delta, ptr->K, ptr->h);
	ptr->calc_sigma_plus = 0;
	ptr->calc_sigma_minus = 0;
	return SR_SUCCESS;
}

static SR_BOOL can_ml_test(ml_can_item_t* item)
{
	SR_32			tmp_calc;
	
	tmp_calc = item->calc_sigma_plus + item->delta - item->mean_delta - item->K;
	item->calc_sigma_plus = (tmp_calc > 0)? tmp_calc : 0;
	tmp_calc = item->calc_sigma_minus - item->delta + item->mean_delta - item->K;
	item->calc_sigma_minus = (tmp_calc > 0)? tmp_calc : 0;
	if (item->calc_sigma_plus > item->h) {
		printf ("msg_id 0x%x blocked by sigma_plus\n",item->msg_id);
		return SR_FALSE;
	} else if (item->calc_sigma_minus > item->h) {
		printf ("msg_id 0x%x blocked by sigma_minus\n",item->msg_id);
		return SR_FALSE;
	}
	printf ("normal\n");
	//if ((item->msg_id == 0x5a0) || (item->msg_id == 0x1a0))
		//printf ("msg_id 0x%x, sigma_plus = %d, sigma_minus = %d, K= %d, h= %d\n",item->msg_id, item->calc_sigma_plus, item->calc_sigma_minus, item->K, item->h);
	return SR_TRUE;
}

static SR_32 update_can_item(SR_U64 ts, SR_U32 msg_id)
{
	ml_can_item_t 	*can_ml_item;
	SR_32 			rc;
	SR_U64			tmp_delta;

	/* If the file exists add the rule to the file. */
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
									"failed to insert mid to can_ml table");
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
			//if ((can_ml_item->msg_id == 0x5a0) || (can_ml_item->msg_id == 0x1a0) || (can_ml_item->msg_id == 0x280))	
				//printf ("msg_id = 0x%x, delta = %d, d_delta = %d\n", can_ml_item->msg_id, can_ml_item->delta, can_ml_item->delta);
			if (learning) {
				can_ml_item->sum_delta+= can_ml_item->delta;
				can_ml_item->samples++;
				if (ts  > LEARNING_TIME) {
					learning = 0;
					sr_gen_hash_exec_for_each(can_ml_hash, calc_K_factors, NULL);
					printf ("learning finished\n");
				}
			} else {
				/* detect mode */
				//printf ("detect mode\n");
				can_ml_test(can_ml_item);
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
