#include <stddef.h>
#include <linux/vsentry/vsentry.h>
#include "prog_cls.h"
#include "bitops.h"
#include "hash.h"
#include "aux.h"
#include "heap.h"

#ifdef PROG_DEBUG
#define prog_dbg cls_dbg
#define prog_err cls_err
#else
#define prog_dbg(...)
#define prog_err(...)
#endif

#define PROG_HASH_NUM_OF_BITS 	10

/* hash item for PROG */
typedef struct __attribute__ ((packed, aligned(8))) {
	unsigned int exec_ino;
	bit_array_t rules;
} prog_hash_item_t;

/* the default rules data struct */
typedef struct __attribute__ ((packed, aligned(8))) {
	bit_array_t	any_rules[CLS_TOTAL_RULE_TYPE];
} prog_any_rules_t;

/* the below struct will hold the hash buckets offsets on the persistent
 * database */
typedef struct __attribute__ ((packed, aligned(8))) {
	unsigned int 	buckets_offsets[CLS_TOTAL_RULE_TYPE];
} prog_buckets_array_t;

/* prog default rules pointers */
static prog_any_rules_t *prog_any_rules = NULL;
/* prog hash buckets offset array */
static prog_buckets_array_t *prog_buckets = NULL;

/* hash key generate function for PROG */
static unsigned int prog_hash_genkey(void *data, unsigned int number_of_bits)
{
	prog_hash_item_t *prog_item = (prog_hash_item_t*)data;

	return hash32(prog_item->exec_ino, PROG_HASH_NUM_OF_BITS);
}

/* compare the hash item vs prog */
static bool prog_hash_compare(void *candidat, void *searched)
{
	prog_hash_item_t *prog_item;
	unsigned int *exec_ino_searched;

	prog_item = (prog_hash_item_t*)candidat;
	exec_ino_searched = (unsigned int*)searched;

	if (*exec_ino_searched == prog_item->exec_ino)
		return true;

	return false;
}

/* print prog item content */
static void prog_print_item(void *data)
{
	prog_hash_item_t *prog_item = (prog_hash_item_t*)data;
	unsigned short bit;

	cls_printf("    exec_ino %u rules: ", prog_item->exec_ino);

	ba_for_each_set_bit(bit, &prog_item->rules)
		cls_printf("%d ", bit);

	cls_printf("\n");
}

/*  global array of 3 prog hashs (can, ip, file) */
static hash_t prog_hash_array[CLS_TOTAL_RULE_TYPE] = {
	{
		.name = "prog_ip_hash",
		.bits = PROG_HASH_NUM_OF_BITS,
	},
	{
		.name = "prog_can_hash",
		.bits = PROG_HASH_NUM_OF_BITS,
	},
	{
		.name = "prog_file_hash",
		.bits = PROG_HASH_NUM_OF_BITS,
	},
};

/* global hash ops struct for prog hash */
static hash_ops_t prog_hash_ops;

/* prog hash init function */
int prog_cls_init(cls_hash_params_t *hash_params)
{
	int i;

	/* init the hash ops */
	prog_hash_ops.comp = prog_hash_compare;
	prog_hash_ops.create_key = prog_hash_genkey;
	prog_hash_ops.print = prog_print_item;

	/* init the 3 prog hash array  ops */
	for (i=0; i<CLS_TOTAL_RULE_TYPE; i++)
		prog_hash_array[i].hash_ops = &prog_hash_ops;

	/* init the default rules */
	if (hash_params->any_offset == 0) {
		/* default rules was not prev allocated. lets allocate */
		prog_any_rules = heap_calloc(sizeof(prog_any_rules_t));
		if (!hash_params) {
			prog_err("failed to allocate prog default rules\n");
			return VSENTRY_ERROR;
		}

		for (i=0; i<CLS_TOTAL_RULE_TYPE; i++)
			prog_any_rules->any_rules[i].empty = true;

		/* update the global database, will be used in the next boot */
		hash_params->any_offset = get_offset(prog_any_rules);
	} else {
		/* restore prev allocated default rules */
		prog_any_rules = get_pointer(hash_params->any_offset);
	}

	/* init the prog hash table */
	if (hash_params->hash_offset == 0 || hash_params->bits != PROG_HASH_NUM_OF_BITS) {
		/* hash was not prev allocated. lets allocate.
		 * first we allocate memory to preserve the buckets offsets */
		prog_buckets = heap_alloc(sizeof(prog_buckets_array_t));
		if (!prog_buckets) {
			prog_err("failed to allocte prog_buckets\n");
			return VSENTRY_ERROR;
		}

		/* aloocate hashs */
		for (i=0; i<CLS_TOTAL_RULE_TYPE; i++) {
			if (hash_create(&prog_hash_array[i]) != VSENTRY_SUCCESS)
				return VSENTRY_ERROR;
			/* save the buckets offsets */
			prog_buckets->buckets_offsets[i] = get_offset(prog_hash_array[i].buckets);
		}

		/* update the global database, will be used in the next boot */
		hash_params->bits = PROG_HASH_NUM_OF_BITS;
		hash_params->hash_offset = get_offset(prog_buckets);
	} else {
		/* restore prev allocated hashs */
		prog_buckets = get_pointer(hash_params->hash_offset);
		for (i=0; i<CLS_TOTAL_RULE_TYPE; i++) {
			prog_hash_array[i].buckets = get_pointer(prog_buckets->buckets_offsets[i]);
			hash_set_ops(&prog_hash_array[i]);
		}
	}

	return VSENTRY_SUCCESS;
}

/* add new prog rule */
int prog_cls_add_rule(cls_rule_type_e type, unsigned int rule, unsigned int exec_ino)
{
	bit_array_t *arr = NULL;
	prog_hash_item_t *prog_item = NULL;
#ifdef PROG_DEBUG
	char *type_name_arr[CLS_TOTAL_RULE_TYPE] = {
	"ip",
	"can",
	"file",
};
#endif

	if (type >= CLS_TOTAL_RULE_TYPE || rule >= MAX_RULES) {
		prog_err("invalid prog rule argument\n");
		return VSENTRY_INVALID;
	}

	if (exec_ino == PROG_ANY) {
		/* default rule */
		arr = &prog_any_rules->any_rules[type];
	} else {
		/* search if this rule already exist */
		prog_item = hash_get_data(&prog_hash_array[type], &exec_ino);
		if (!prog_item) {
			/* allocate new prog_item */
			prog_item = heap_calloc(sizeof(prog_hash_item_t));
			if (!prog_item) {
				prog_err("failed to allocate new prog item\n");
				return VSENTRY_ERROR;
			}

			prog_item->exec_ino = exec_ino;
			/* insert new item to prog hash */
			hash_insert_data(&prog_hash_array[type], prog_item);
			prog_dbg("created new %s prog inode %u\n", type_name_arr[type], exec_ino);
		}

		arr = &prog_item->rules;
	}

	/* set the rule bit ib the relevant bit array */
	ba_set_bit(rule, arr);
	prog_dbg("set bit %u on %s prog inode %u\n", rule, type_name_arr[type], exec_ino);

	return VSENTRY_SUCCESS;
}

int prog_cls_del_rule(cls_rule_type_e type, unsigned int rule, unsigned int exec_ino)
{
	bit_array_t *arr = NULL;
	prog_hash_item_t *prog_item = NULL;

	if (type >= CLS_TOTAL_RULE_TYPE || rule >= MAX_RULES) {
		prog_err("invalid prog rule argument\n");
		return VSENTRY_INVALID;
	}

	if (exec_ino == PROG_ANY) {
		arr = &prog_any_rules->any_rules[type];
	} else {
		/* search if this data already exist */
		prog_item = hash_get_data(&prog_hash_array[type], &exec_ino);
		if (!prog_item)
			return VSENTRY_NONE_EXISTS;

		arr = &prog_item->rules;
	}

	if (!ba_is_set(rule, arr))
		return VSENTRY_NONE_EXISTS;

	/* clear the rule bit */
	ba_clear_bit(rule, arr);

	/* if no more bit are set delete the entry */
	if (prog_item && ba_is_empty(arr))
		hash_delete_data(&prog_hash_array[type], (void*)&exec_ino);

	return VSENTRY_SUCCESS;
}

/* classification function. find the matched bit array (if any)
 * and AND it with verdict */
int prog_cls_search(cls_rule_type_e type, id_event_t *data, bit_array_t *verdict)
{
	bit_array_t *arr_any = NULL;
	prog_hash_item_t *prog_item = NULL;

	if (type >= CLS_TOTAL_RULE_TYPE) {
		prog_err("invalid prog rule argument\n");
		return VSENTRY_INVALID;
	}

	arr_any = &prog_any_rules->any_rules[type];

	/* search if this data exist */
	prog_item = hash_get_data(&prog_hash_array[type], &data->exec_ino);
	if (prog_item) {
		ba_and(verdict, verdict, &prog_item->rules);
		/* if any rule is active, or it */
		if (!ba_is_empty(arr_any))
			ba_or(verdict, verdict, arr_any);

		return VSENTRY_SUCCESS;
	}

	if (cls_get_mode() == CLS_MODE_LEARN) {
		/* in learn mode we dont want to get the default rule
		 * since we want to learn this event, so we clear the
		 * verdict bitmap to signal no match */
		ba_clear(verdict);

		return VSENTRY_SUCCESS;
	}

	/* if no specific rule and it with any*/
	ba_and(verdict, verdict, arr_any);

	return VSENTRY_SUCCESS;
}

int prog_find_free_rule(cls_rule_type_e type, unsigned int prog)
{
	prog_hash_item_t *prog_item = NULL;

	if (type >= CLS_TOTAL_RULE_TYPE) {
		prog_err("invalid prog rule argument\n");
		return VSENTRY_INVALID;
	}

	/* search if this data exist */
	prog_item = hash_get_data(&prog_hash_array[type], &prog);
	if (!prog_item)
		return VSENTRY_NONE_EXISTS;

	return find_first_zero_bit(prog_item->rules.bitmap, MAX_RULES);
}

/* pritn all prog hash array */
void prog_print_hash(void)
{
	unsigned short bit;
	unsigned int i;

	cls_printf("exec_ino db:\n");

	for (i=0; i<CLS_TOTAL_RULE_TYPE; i++) {
		cls_printf("  hash %s\n", prog_hash_array[i].name);
		hash_print(&prog_hash_array[i]);
	}

	cls_printf("  any ip : ");
	ba_for_each_set_bit(bit, &prog_any_rules->any_rules[CLS_IP_RULE_TYPE])
		cls_printf("%d ", bit);
	cls_printf("\n");

	cls_printf("  any can : ");
	ba_for_each_set_bit(bit, &prog_any_rules->any_rules[CLS_CAN_RULE_TYPE])
		cls_printf("%d ", bit);
	cls_printf("\n");

	cls_printf("  any file : ");
	ba_for_each_set_bit(bit, &prog_any_rules->any_rules[CLS_FILE_RULE_TYPE])
		cls_printf("%d ", bit);
	cls_printf("\n");

	cls_printf("\n");
}
