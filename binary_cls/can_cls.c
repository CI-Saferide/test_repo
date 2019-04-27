#include <stddef.h>
#include "can_cls.h"
#include "bitops.h"
#include "hash.h"
#include "aux.h"
#include "heap.h"

#ifdef CAN_DEBUG
#define can_dbg cls_dbg
#define can_err cls_err

static char *get_can_dir_str(unsigned int dir)
{
	switch (dir) {
	case DIR_IN:
		return "in";
	case DIR_OUT:
		return "out";
	default:
		return "n\a";
	}
}

#else
#define can_dbg(...)
#define can_err(...)
#endif

#define CAN_HASH_NUM_OF_BITS 	10

/* hash item for CAN */
typedef struct __attribute__ ((aligned(8))) {
	can_header_t can_data;
	unsigned int counter;
	bit_array_t rules;
} can_hash_item_t;

/* the default rules data struct */
typedef struct __attribute__ ((aligned(8))) {
	bit_array_t	any_rules[DIR_TOTAL];
} any_rules_t;

/* the below struct will hold the hash buckets offsets on the persistent
 * database */
typedef struct __attribute__ ((aligned(8))) {
	unsigned int 	buckets_offsets[DIR_TOTAL];
} can_buckets_array_t;

/* can default rules */
static any_rules_t *can_any_rules = NULL;
/* can hash buckets offset array */
static can_buckets_array_t *can_buckets = NULL;

/* hash key generate function for CAN */
static unsigned int can_hash_genkey(void *data, unsigned int number_of_bits)
{
	unsigned int key, key1, key2;
	can_hash_item_t *can_item = (can_hash_item_t*)data;

	/* this function generates a 32 bit key from msg_id and if_idx */
	/* key[bit31-bit28] = interface index */
	key1 = ((hash32(can_item->can_data.if_index, 4) & 0xF) << 28);

	/* key[bit27-bit0] = msg_id */
	key2 = ((hash32(can_item->can_data.msg_id, 28)) & 0xFFFFFFF);

	key = hash32((key1 | key2), CAN_HASH_NUM_OF_BITS);

	return key;
}

/* compare the hash item vs can */
static bool can_hash_compare(void *candidat, void *searched)
{
	can_hash_item_t *can_candidat;
	can_header_t *can_searched;

	can_candidat = (can_hash_item_t*)candidat;
	can_searched = (can_header_t*)searched;

	if ((can_candidat->can_data.msg_id == can_searched->msg_id) &&
			(can_candidat->can_data.if_index == can_searched->if_index))
		return true;

	return false;
}

#ifdef CLS_DEBUG
/* print can item content */
static void can_print_item(void *data)
{
	can_hash_item_t *can_item = (can_hash_item_t*)data;

	cls_printf("    msg_id 0x%08x if %d rules: ",
		can_item->can_data.msg_id, can_item->can_data.if_index);

	ba_print_set_bits(&can_item->rules);
}
#endif

/*  global array of 2 (per direction) can hashs */
static hash_t can_hash_array[DIR_TOTAL] = {
	{
		.name = "can_in_hash",
		.bits = CAN_HASH_NUM_OF_BITS,
	},
	{
		.name = "can_out_hash",
		.bits = CAN_HASH_NUM_OF_BITS,
	}
};

/* global hash ops struct for can hash */
static hash_ops_t can_hash_ops;

/* can hash init function */
int can_cls_init(cls_hash_params_t *hash_params)
{
	int i;

	/* init the hash ops */
	can_hash_ops.comp = can_hash_compare;
	can_hash_ops.create_key = can_hash_genkey;
#ifdef CLS_DEBUG
	can_hash_ops.print = can_print_item;
#endif

	/* init the 3 uid hash array ops */
	for (i=0; i<DIR_TOTAL; i++)
		can_hash_array[i].hash_ops = &can_hash_ops;

	/* init the any rules */
	if (hash_params->any_offset == 0) {
		/* any rules was not prev allocated. lets allocate */
		can_any_rules = heap_calloc(sizeof(any_rules_t));
		if (!can_any_rules) {
			can_err("failed to allocate can default rules\n");
			return VSENTRY_ERROR;
		}

		for (i=0; i<DIR_TOTAL; i++)
			can_any_rules->any_rules[i].empty = true;

		/* update the global database, will be used in the next boot */
		hash_params->any_offset = get_offset(can_any_rules);
	} else {
		/* restore prev allocated default rules */
		can_any_rules = get_pointer(hash_params->any_offset);
	}

	/* init the can hash table */
	if (hash_params->hash_offset == 0 || hash_params->bits != CAN_HASH_NUM_OF_BITS) {
		/* hash was not prev allocated. lets allocate.
		 * first we allocate memory to preserve the buckets offsets */
		can_buckets = heap_calloc(sizeof(can_buckets_array_t));
		if (!can_buckets) {
			can_err("failed to allocate can_buckets\n");
			return VSENTRY_ERROR;
		}

		/* allocate hashes */
		for (i=0; i<DIR_TOTAL; i++) {
			if (hash_create(&can_hash_array[i]) != VSENTRY_SUCCESS)
				return VSENTRY_ERROR;
			/* save the buckets offsets */
			can_buckets->buckets_offsets[i] = get_offset(can_hash_array[i].buckets);
		}

		/* update the global database, will be used in the next boot */
		hash_params->bits = CAN_HASH_NUM_OF_BITS;
		hash_params->hash_offset = get_offset(can_buckets);
	} else {
		/* restore prev allocated hashs */
		can_buckets = get_pointer(hash_params->hash_offset);
		for (i=0; i<DIR_TOTAL; i++) {
			can_hash_array[i].buckets = get_pointer(can_buckets->buckets_offsets[i]);
			hash_set_ops(&can_hash_array[i]);
		}
	}

	return VSENTRY_SUCCESS;
}

static inline int can_cls_check_valid(can_header_t *data, unsigned int dir)
{
	if (data->if_index >= CAN_MAX_IF_INDEX)
		return VSENTRY_ERROR;

	if (dir >= DIR_TOTAL)
		return VSENTRY_ERROR;

	if ((data->msg_id > MAX_CAN_MSG_ID) && (data->msg_id !=  MSGID_ANY))
		return VSENTRY_ERROR;

	return VSENTRY_SUCCESS;
}

int can_cls_add_rule(unsigned int rule, can_header_t *data, unsigned int dir)
{
	bit_array_t *arr = NULL;
	can_hash_item_t *can_item = NULL;

	if (can_cls_check_valid(data, dir))
		return VSENTRY_ERROR;

	can_dbg("add can rule mid 0x%x dir %s if_index %u\n",
			data->msg_id , get_can_dir_str(dir), data->if_index);

	if (rule >= MAX_RULES)
		return VSENTRY_ERROR;

	if (data->msg_id == MSGID_ANY) {
		arr = &can_any_rules->any_rules[dir];
	} else {
		/* search if this data already exist */
		can_item = hash_get_data(&can_hash_array[dir], data);
		if (!can_item) {
			/* allocate new can_item */
			can_item = heap_calloc(sizeof(can_hash_item_t));
			if (!can_item)
				return VSENTRY_ERROR;

			can_item->rules.empty = true;
			vs_memcpy(&can_item->can_data, data, sizeof(can_header_t));
			hash_insert_data(&can_hash_array[dir], can_item);
			can_dbg("created new can rule mid 0x%x dir %s if_index %u\n",
				data->msg_id , get_can_dir_str(dir), data->if_index);
		}

		arr = &can_item->rules;
	}

	if (!ba_is_set(rule, arr)) {
		ba_set_bit(rule, arr);
		can_dbg("set bit %u on can rule mid 0x%x dir %s if_index %u\n",
			rule, data->msg_id , get_can_dir_str(dir), data->if_index);
	}

	return VSENTRY_SUCCESS;
}

int can_cls_del_rule(unsigned int rule, can_header_t *data, unsigned int dir)
{
	bit_array_t *arr = NULL;
	can_hash_item_t *can_item = NULL;

	if (can_cls_check_valid(data, dir))
		return VSENTRY_ERROR;

	if (rule >= MAX_RULES)
		return VSENTRY_ERROR;

	if (data->msg_id == MSGID_ANY) {
		arr = &can_any_rules->any_rules[dir];
	} else {
		/* search if this data already exist */
		can_item = hash_get_data(&can_hash_array[dir], data);
		if (!can_item) {
			can_err("could not find mid 0x%x dir %s if %u\n",
				data->msg_id, get_can_dir_str(dir), data->if_index);
			return VSENTRY_NONE_EXISTS;
		}

		arr = &can_item->rules;
	}

	if (!ba_is_set(rule, arr))
		return VSENTRY_NONE_EXISTS;

	/* clear the rule bit */
	ba_clear_bit(rule, arr);
	can_dbg("clear bit %u on can rule mid 0x%x dir %s if_index %u\n",
		rule, data->msg_id , get_can_dir_str(dir), data->if_index);

	/* if no more bit are set delete the entry */
	if (can_item && ba_is_empty(arr)) {
		can_dbg("deleting can rule mid 0x%x dir %s if_index %u\n",
			data->msg_id , get_can_dir_str(dir), data->if_index);
		hash_delete_data(&can_hash_array[dir], data);
	}

	return VSENTRY_SUCCESS;
}

int can_cls_search(vsentry_event_t *can_ev, bit_array_t *verdict)
{
	bit_array_t *arr_any = NULL;
	can_hash_item_t *can_item = NULL;

	if (can_cls_check_valid(&can_ev->can_event.can_header, can_ev->dir))
		return VSENTRY_ERROR;

	arr_any = &can_any_rules->any_rules[can_ev->dir];

	/* search if this data exist */
	can_item = hash_get_data(&can_hash_array[can_ev->dir], &can_ev->can_event.can_header);
	if (can_item) {
		__sync_add_and_fetch(&can_item->counter, 1);

		if (!ba_is_empty(arr_any))
			/* if we have non-empty ANY rule , verdict calculation:
			 * verdict = verdict & (ANY | RULE)*/
			ba_and_or(verdict, verdict, &can_item->rules, arr_any);
		else
			/* no ANY rule, just AND verdict with specific rule */
			ba_and(verdict, verdict, &can_item->rules);

		return VSENTRY_SUCCESS;
	}

#ifdef ENABLE_LEARN
	if (cls_get_mode() == VSENTRY_MODE_LEARN) {
		/* in learn mode we dont want to get the default rule
		 * since we want to learn this event, so we clear the
		 * verdict bitmap to signal no match */
		ba_clear(verdict);

		return VSENTRY_SUCCESS;
	}
#endif

	/* no specific rule, just AND verdict with ANY rule */
	ba_and(verdict, verdict, arr_any);

	return VSENTRY_SUCCESS;
}

typedef struct {
	int start;
	int end;
	int dir;
} can_rules_limit_t;

static void check_can_rule(void *data, void* param)
{
	int i;
	can_hash_item_t *can_item = data;
	can_rules_limit_t* limit = param;

	for (i=limit->start; i<limit->end; i++) {
		if (ba_is_set(i, &can_item->rules))
			can_cls_del_rule(i, &can_item->can_data, limit->dir);
	}
}

void can_cls_clear_rules(int start, int end)
{
	int i;
	can_rules_limit_t limit = {
		.start = start,
		.end = end,
	};

	for (i=0; i<DIR_TOTAL; i++) {
		limit.dir = i;
		hash_walk(&can_hash_array[i], check_can_rule, &limit);
	}
}

#ifdef CLS_DEBUG
void can_print_hash(void)
{
	int i;

	cls_printf("can db:\n");
	for (i=0; i<DIR_TOTAL; i++) {
		cls_printf("  hash %s\n", can_hash_array[i].name);
		hash_print(&can_hash_array[i]);
	}

	cls_printf("  any in: ");
	ba_print_set_bits(&can_any_rules->any_rules[DIR_IN]);

	cls_printf("  any out: ");
	ba_print_set_bits(&can_any_rules->any_rules[DIR_OUT]);

	cls_printf("\n");
}
#endif
