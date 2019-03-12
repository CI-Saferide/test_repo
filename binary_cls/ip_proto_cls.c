#include <stddef.h>
#include <linux/vsentry/vsentry.h>
#include "ip_proto_cls.h"
#include "bitops.h"
#include "hash.h"
#include "aux.h"
#include "heap.h"
#include "classifier.h"

#ifdef IP_PROTO_DEBUG
#define ip_proto_dbg cls_dbg
#define ip_proto_err cls_err
#else
#define ip_proto_dbg(...)
#define ip_proto_err(...)
#endif

#define IP_PROTO_HASH_NUM_OF_BITS 	5

/* hash item for IP_PROTO */
typedef struct __attribute__ ((packed, aligned(8))) {
	unsigned char ip_proto;
	bit_array_t rules;
} ip_proto_hash_item_t;

/* the default rules data struct */
typedef struct __attribute__ ((packed, aligned(8))) {
	bit_array_t	any_rules;
} ip_proto_any_rules_t;

/* the below struct will hold the hash buckets offsets on the persistent
 * database */
typedef struct __attribute__ ((packed, aligned(8))) {
	unsigned int 	buckets_offsets;
} ip_proto_bucket_t;

/* ip_proto default rules pointers */
static ip_proto_any_rules_t *ip_proto_any_rules = NULL;
/* ip_proto hash buckets offset array */
static ip_proto_bucket_t *ip_proto_buckets = NULL;

/* hash key generate function for PROG */
static unsigned int ip_proto_hash_genkey(void *data, unsigned int number_of_bits)
{
	ip_proto_hash_item_t *ip_proto_item = (ip_proto_hash_item_t*)data;

	return hash32(ip_proto_item->ip_proto, IP_PROTO_HASH_NUM_OF_BITS);
}

/* compare the hash item vs prog */
static bool ip_proto_hash_compare(void *candidat, void *searched)
{
	ip_proto_hash_item_t *ip_proto_item;
	unsigned char *ip_proto;

	ip_proto_item = (ip_proto_hash_item_t*)candidat;
	ip_proto = (unsigned char*)searched;

	if (*ip_proto == ip_proto_item->ip_proto)
		return true;

	return false;
}

/* print prog item content */
static void ip_proto_print_item(void *data)
{
	ip_proto_hash_item_t *ip_proto_item = (ip_proto_hash_item_t*)data;
	unsigned short bit;

	cls_printf("    ip_proto %u rules: ", ip_proto_item->ip_proto);

	ba_for_each_set_bit(bit, &ip_proto_item->rules)
		cls_printf("%d ", bit);

	cls_printf("\n");
}

/*  global ip_proto hash */
static hash_t ip_proto_hash_array = {
	.name = "ip_proto_hash",
		.bits = IP_PROTO_HASH_NUM_OF_BITS,
};

/* global hash ops struct for prog hash */
static hash_ops_t ip_proto_hash_ops;

/* prog hash init function */
int ip_proto_cls_init(cls_hash_params_t *hash_params)
{
	/* init the hash ops */
	ip_proto_hash_ops.comp = ip_proto_hash_compare;
	ip_proto_hash_ops.create_key = ip_proto_hash_genkey;
	ip_proto_hash_ops.print = ip_proto_print_item;

	/* init the ip_proto hash array  ops */
	ip_proto_hash_array.hash_ops = &ip_proto_hash_ops;

	/* init the default rules */
	if (hash_params->any_offset == 0) {
		/* default rules was not prev allocated. lets allocate */
		ip_proto_any_rules = heap_calloc(sizeof(ip_proto_any_rules_t));
		if (!hash_params) {
			ip_proto_err("failed to allocate prog default rules\n");
			return VSENTRY_ERROR;
		}

		ip_proto_any_rules->any_rules.empty = true;
		

		/* update the global database, will be used in the next boot */
		hash_params->any_offset = get_offset(ip_proto_any_rules);
	} else {
		/* restore prev allocated default rules */
		ip_proto_any_rules = get_pointer(hash_params->any_offset);
	}

	/* init the prog hash table */
	if (hash_params->hash_offset == 0 || hash_params->bits != IP_PROTO_HASH_NUM_OF_BITS) {
		/* hash was not prev allocated. lets allocate.
		 * first we allocate memory to preserve the buckets offsets */
		ip_proto_buckets = heap_alloc(sizeof(ip_proto_bucket_t));
		if (!ip_proto_buckets) {
			ip_proto_err("failed to allocate ip_proto_buckets\n");
			return VSENTRY_ERROR;
		}

		/* allocate hashs */
		if (hash_create(&ip_proto_hash_array) != VSENTRY_SUCCESS)
			return VSENTRY_ERROR;
	
		/* save the buckets offsets */
		ip_proto_buckets->buckets_offsets = get_offset(ip_proto_hash_array.buckets);

		/* update the global database, will be used in the next boot */
		hash_params->bits = IP_PROTO_HASH_NUM_OF_BITS;
		hash_params->hash_offset = get_offset(ip_proto_buckets);
	} else {
		/* restore prev allocated hashs */
		ip_proto_buckets = get_pointer(hash_params->hash_offset);
		ip_proto_hash_array.buckets = get_pointer(ip_proto_buckets->buckets_offsets);
		hash_set_ops(&ip_proto_hash_array);
	}

	return VSENTRY_SUCCESS;
}

/* add new prog rule */
int ip_proto_cls_add_rule(unsigned int rule, unsigned int proto)
{
	bit_array_t *arr = NULL;
	ip_proto_hash_item_t *ip_proto_item = NULL;

	if (rule >= MAX_RULES) {
		ip_proto_err("invalid rule argument\n");
		return VSENTRY_INVALID;
	}

	if ((proto != IP_PROTO_ANY) && (proto > (unsigned char)(-1))) {
		ip_proto_err("invalid ip_proto argument\n");
		return VSENTRY_INVALID;
	}

	if (proto == IP_PROTO_ANY) {
		arr = &ip_proto_any_rules->any_rules;
	} else {
		/* search if this rule already exist */
		ip_proto_item = hash_get_data(&ip_proto_hash_array, &proto);
		if (!ip_proto_item) {
			/* allocate new ip_proto_item */
			ip_proto_item = heap_calloc(sizeof(ip_proto_hash_item_t));
			if (!ip_proto_item) {
				ip_proto_err("failed to allocate new prog item\n");
				return VSENTRY_ERROR;
			}

			ip_proto_item->rules.empty = true;
			ip_proto_item->ip_proto = proto;

			/* insert new item to hash */
			hash_insert_data(&ip_proto_hash_array, ip_proto_item);
		}

		arr = &ip_proto_item->rules;
	}

	/* set the rule bit in the relevant bit array */
	ba_set_bit(rule, arr);

	return VSENTRY_SUCCESS;
}

int ip_proto_cls_del_rule(unsigned int rule, unsigned int proto)
{
	bit_array_t *arr = NULL;
	ip_proto_hash_item_t *ip_proto_item = NULL;

	if (rule >= MAX_RULES) {
		ip_proto_err("invalid rule argument\n");
		return VSENTRY_INVALID;
	}

	if ((proto != IP_PROTO_ANY) && (proto > (unsigned short)(-1))) {
		ip_proto_err("invalid ip_proto argument\n");
		return VSENTRY_INVALID;
	}

	if (proto == IP_PROTO_ANY) {
		arr = &ip_proto_any_rules->any_rules;
	} else {
		/* search if this data already exist */
		ip_proto_item = hash_get_data(&ip_proto_hash_array, &proto);
		if (!ip_proto_item)
			return VSENTRY_NONE_EXISTS;

		arr = &ip_proto_item->rules;
	}

	if (!ba_is_set(rule, arr))
		return VSENTRY_NONE_EXISTS;

	/* clear the rule bit */
	ba_clear_bit(rule, arr);

	/* if no more bit are set delete the entry */
	if (ip_proto_item && ba_is_empty(arr))
		hash_delete_data(&ip_proto_hash_array, (void*)&proto);

	return VSENTRY_SUCCESS;
}

/* classification function. find the matched bit array (if any)
 * and AND it with verdict */
int ip_proto_cls_search(ip_event_t *data, bit_array_t *verdict)
{
	bit_array_t *arr = NULL;
	ip_proto_hash_item_t *ip_proto_item = NULL;

	if ((data->ip_proto != IP_PROTO_ANY) && (data->ip_proto > (unsigned short)(-1))) {
		ip_proto_err("invalid ip_proto argument\n");
		return VSENTRY_INVALID;
	}

	/* search if this data exist */
	ip_proto_item = hash_get_data(&ip_proto_hash_array, &data->ip_proto);
	if (ip_proto_item) {
		arr = &ip_proto_item->rules;
	} else {
		if (cls_get_mode() == CLS_MODE_LEARN) {
			/* in learn mode we dont want to get the default rule
			 * since we want to learn this event, so we clear the
			 * verdict bitmap to signal no match */
			ba_clear(verdict);

			return VSENTRY_SUCCESS;
		}
		/* use the default rule if no item was found */
		arr = &ip_proto_any_rules->any_rules;
	}

	ba_and(verdict, verdict, arr);

	return VSENTRY_SUCCESS;
}

/* pritn all prog hash array */
void ip_proto_print_hash(void)
{
	unsigned short bit;

	cls_printf("ip_proto db:\n");

	cls_printf("  hash %s\n", ip_proto_hash_array.name);
	hash_print(&ip_proto_hash_array);

	cls_printf("  any ip_prot: ");
	ba_for_each_set_bit(bit, &ip_proto_any_rules->any_rules)
		cls_printf("%d ", bit);
	cls_printf("\n");

	cls_printf("\n");
}
