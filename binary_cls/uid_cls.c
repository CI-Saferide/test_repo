#include <stddef.h>
#include <linux/vsentry/vsentry.h>
#include "uid_cls.h"
#include "bitops.h"
#include "hash.h"
#include "aux.h"
#include "heap.h"

#ifdef UID_DEBUG
#define uid_dbg cls_dbg
#define uid_err cls_err
#else
#define uid_dbg(...)
#define uid_err(...)
#endif

#define UID_HASH_NUM_OF_BITS 	10

/* hash item for UID */
typedef struct __attribute__ ((packed, aligned(8))) {
	unsigned int uid;
	bit_array_t rules;
} uid_hash_item_t;

/* the default rules data struct */
typedef struct __attribute__ ((packed, aligned(8))) {
	bit_array_t	any_rules[CLS_TOTAL_RULE_TYPE];
} uid_any_rules_t;

/* the below struct will hold the hash buckets offsets on the persistent
 * database */
typedef struct __attribute__ ((packed, aligned(8))) {
	unsigned int 	buckets_offsets[CLS_TOTAL_RULE_TYPE];
} uid_buckets_array_t;

/* uid default rules pointers */
static uid_any_rules_t *uid_any_rules = NULL;
/* uid hash buckets offset array */
static uid_buckets_array_t *uid_buckets = NULL;

/* hash key generate function for UID */
static unsigned int uid_hash_genkey(void *data, unsigned int number_of_bits)
{
	uid_hash_item_t *uid_item = (uid_hash_item_t*)data;

	return hash32(uid_item->uid, UID_HASH_NUM_OF_BITS);
}

/* compare the hash item vs uid */
static bool uid_hash_compare(void *candidat, void *searched)
{
	uid_hash_item_t *uid_item;
	unsigned int *uid_searched;

	uid_item = (uid_hash_item_t*)candidat;
	uid_searched = (unsigned int*)searched;

	if (*uid_searched == uid_item->uid)
		return true;

	return false;
}

/* print uid item content */
static void uid_print_item(void *data)
{
	uid_hash_item_t *uid_item = (uid_hash_item_t*)data;
	unsigned short bit;

	cls_printf("    uid %u rules: ", uid_item->uid);

	ba_for_each_set_bit(bit, &uid_item->rules)
		cls_printf("%d ", bit);

	cls_printf("\n");
}

/*  global array of 3 uid hashs (can, ip, file) */
static hash_t uid_hash_array[CLS_TOTAL_RULE_TYPE] = {
	{
		.name = "uid_ip_hash",
		.bits = UID_HASH_NUM_OF_BITS,
	},
	{
		.name = "uid_can_hash",
		.bits = UID_HASH_NUM_OF_BITS,
	},
	{
		.name = "uid_file_hash",
		.bits = UID_HASH_NUM_OF_BITS,
	},
};

/* global hash ops struct for uid hash */
static hash_ops_t uid_hash_ops;

/* uid hash init function */
int uid_cls_init(cls_hash_params_t *hash_params)
{
	int i;

	/* init the hash ops */
	uid_hash_ops.comp = uid_hash_compare;
	uid_hash_ops.create_key = uid_hash_genkey;
	uid_hash_ops.print = uid_print_item;

	/* init the 3 uid hash array  ops */
	for (i=0; i<CLS_TOTAL_RULE_TYPE; i++)
		uid_hash_array[i].hash_ops = &uid_hash_ops;

	/* init the default rules */
	if (hash_params->any_offset == 0) {
		/* default rules was not prev allocated. lets allocate */
		uid_any_rules = heap_calloc(sizeof(uid_any_rules_t));
		if (!hash_params) {
			uid_err("failed to allocate uid default rules\n");
			return VSENTRY_ERROR;
		}

		for (i=0; i<CLS_TOTAL_RULE_TYPE; i++)
			uid_any_rules->any_rules[i].empty = true;

		/* update the global database, will be used in the next boot */
		hash_params->any_offset = get_offset(uid_any_rules);
	} else {
		/* restore prev allocated default rules */
		uid_any_rules = get_pointer(hash_params->any_offset);
	}

	/* init the uid hash table */
	if (hash_params->hash_offset == 0 || hash_params->bits != UID_HASH_NUM_OF_BITS) {
		/* hash was not prev allocated. lets allocate.
		 * first we allocate memory to preserve the buckets offsets */
		uid_buckets = heap_alloc(sizeof(uid_buckets_array_t));
		if (!uid_buckets) {
			uid_err("failed to allocte uid_buckets\n");
			return VSENTRY_ERROR;
		}

		/* allocte hashs */
		for (i=0; i<CLS_TOTAL_RULE_TYPE; i++) {
			if (hash_create(&uid_hash_array[i]) != VSENTRY_SUCCESS)
				return VSENTRY_ERROR;
			/* save the buckets offsets */
			uid_buckets->buckets_offsets[i] = get_offset(uid_hash_array[i].buckets);
		}

		/* update the global database, will be used in the next boot */
		hash_params->bits = UID_HASH_NUM_OF_BITS;
		hash_params->hash_offset = get_offset(uid_buckets);
	} else {
		/* restore prev allocated hashs */
		uid_buckets = get_pointer(hash_params->hash_offset);
		for (i=0; i<CLS_TOTAL_RULE_TYPE; i++) {
			uid_hash_array[i].buckets = get_pointer(uid_buckets->buckets_offsets[i]);
			hash_set_ops(&uid_hash_array[i]);
		}
	}

	return VSENTRY_SUCCESS;
}

/* add new uid rule */
int uid_cls_add_rule(cls_rule_type_e type, unsigned int rule, unsigned int uid)
{
	bit_array_t *arr = NULL;
	uid_hash_item_t *uid_item = NULL;
#ifdef UID_DEBUG
	char *type_name_arr[CLS_TOTAL_RULE_TYPE] = {
	"ip",
	"can",
	"file",
};
#endif
	if (type >= CLS_TOTAL_RULE_TYPE || rule >= MAX_RULES) {
		uid_err("invalid uid rule argument\n");
		return VSENTRY_INVALID;
	}

	if (uid == UID_ANY) {
		/* default rule */
		arr = &uid_any_rules->any_rules[type];
	} else {
		/* search if this rule already exist */
		uid_item = hash_get_data(&uid_hash_array[type], &uid);
		if (!uid_item) {
			/* allocate new uid_item */
			uid_item = heap_calloc(sizeof(uid_hash_item_t));
			if (!uid_item) {
				uid_err("failed to allocate new uid item\n");
				return VSENTRY_ERROR;
			}

			uid_item->uid = uid;
			/* insert new item to uid hash */
			hash_insert_data(&uid_hash_array[type], uid_item);
			uid_dbg("created new %s uid %u\n", type_name_arr[type], uid);
		}

		arr = &uid_item->rules;
	}

	/* set the rule bit ib the relevant bit array */
	ba_set_bit(rule, arr);
	uid_dbg("set bit %u on %s uid %u\n", rule, type_name_arr[type], uid);

	return VSENTRY_SUCCESS;
}

int uid_cls_del_rule(cls_rule_type_e type, unsigned int rule, unsigned int uid)
{
	bit_array_t *arr = NULL;
	uid_hash_item_t *uid_item = NULL;

	if (type >= CLS_TOTAL_RULE_TYPE || rule >= MAX_RULES) {
		uid_err("invalid uid rule argument\n");
		return VSENTRY_INVALID;
	}

	if (uid == UID_ANY) {
		arr = &uid_any_rules->any_rules[type];
	} else {
		/* search if this data already exist */
		uid_item = hash_get_data(&uid_hash_array[type], &uid);
		if (!uid_item)
			return VSENTRY_NONE_EXISTS;

		arr = &uid_item->rules;
	}

	if (!ba_is_set(rule, arr))
		return VSENTRY_NONE_EXISTS;

	/* clear the rule bit */
	ba_clear_bit(rule, arr);

	/* if no more bit are set delete the entry */
	if (uid_item && ba_is_empty(arr))
		hash_delete_data(&uid_hash_array[type], (void*)&uid);

	return VSENTRY_SUCCESS;
}

/* classification function. find the matched bit array (if any)
 * and AND it with verdict */
int uid_cls_search(cls_rule_type_e type, id_event_t *data, bit_array_t *verdict)
{
	bit_array_t *arr_any = NULL;
	uid_hash_item_t *uid_item = NULL;

	if (type >= CLS_TOTAL_RULE_TYPE) {
		uid_err("invalid uid rule argument\n");
		return VSENTRY_INVALID;
	}

	arr_any = &uid_any_rules->any_rules[type];

	/* search if this data exist */
	uid_item = hash_get_data(&uid_hash_array[type], &data->uid);
	if (uid_item) {
		if (!ba_is_empty(arr_any))
			/* if we have non-empty ANY rule , verdict calculation:
			 * verdict = verdict & (ANY | RULE)*/
			ba_and_or(verdict, verdict, &uid_item->rules, arr_any);
		else
			/* no ANY rule, just AND verdict with specific rule */
			ba_and(verdict, verdict, &uid_item->rules);

		return VSENTRY_SUCCESS;
	}

#ifdef ENABLE_LEARN
	if (cls_get_mode() == CLS_MODE_LEARN) {
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

int uid_find_free_rule(cls_rule_type_e type, unsigned int uid)
{
	uid_hash_item_t *uid_item = NULL;

	if (type >= CLS_TOTAL_RULE_TYPE) {
		uid_err("invalid uid rule argument\n");
		return VSENTRY_INVALID;
	}

	/* search if this data exist */
	uid_item = hash_get_data(&uid_hash_array[type], &uid);
	if (!uid_item)
		return VSENTRY_NONE_EXISTS;

	return find_first_zero_bit(uid_item->rules.bitmap, MAX_RULES);
}

/* print all uid hash array */
void uid_print_hash(void)
{
	unsigned short bit;
	unsigned int i;

	cls_printf("uid db:\n");

	for (i=0; i<CLS_TOTAL_RULE_TYPE; i++) {
		cls_printf("  hash %s\n", uid_hash_array[i].name);
		hash_print(&uid_hash_array[i]);
	}

	cls_printf("  any ip : ");
	ba_for_each_set_bit(bit, &uid_any_rules->any_rules[CLS_IP_RULE_TYPE])
		cls_printf("%d ", bit);
	cls_printf("\n");

	cls_printf("  any can : ");
	ba_for_each_set_bit(bit, &uid_any_rules->any_rules[CLS_CAN_RULE_TYPE])
		cls_printf("%d ", bit);
	cls_printf("\n");

	cls_printf("  any file : ");
	ba_for_each_set_bit(bit, &uid_any_rules->any_rules[CLS_FILE_RULE_TYPE])
		cls_printf("%d ", bit);
	cls_printf("\n");

	cls_printf("\n");
}
