#include <stddef.h>
#include <netinet/in.h>
#include <linux/vsentry/vsentry.h>
#include "classifier.h"
#include "port_cls.h"
#include "bitops.h"
#include "hash.h"
#include "aux.h"
#include "heap.h"

#ifdef PORT_DEBUG
#define port_dbg cls_dbg
#define port_err cls_err
#else
#define port_dbg(...)
#define port_err(...)
#endif

#define PORT_HASH_NUM_OF_BITS 	5

typedef enum {
	PORT_TYPE_TCP,
	PORT_TYPE_UDP,
	PORT_TYPE_TOTAL,
} port_type_e;

/* hash item for PORT */
typedef struct __attribute__ ((aligned(8))) {
	unsigned short 	port;
	bit_array_t 	rules;
} port_hash_item_t;

/* the default rules data struct */
typedef struct __attribute__ ((aligned(8))) {
	bit_array_t	any_rules[CLS_NET_DIR_TOTAL][PORT_TYPE_TOTAL];
} any_rules_t;

/* the below struct will hold the hash buckets offsets on the persistent
 * database */
typedef struct __attribute__ ((aligned(8))) {
	unsigned int 	buckets_offsets[CLS_NET_DIR_TOTAL][PORT_TYPE_TOTAL];
} port_buckets_array_t;

/* port default rules */
static any_rules_t *port_any_rules = NULL;
/* port hash buckets offset array */
static port_buckets_array_t *port_buckets = NULL;

/* hash key generate function for PORT */
static unsigned int port_hash_genkey(void *data, unsigned int number_of_bits)
{
	port_hash_item_t *port_item = (port_hash_item_t*)data;

	return hash32(port_item->port, PORT_HASH_NUM_OF_BITS);
}

/* compare the hash item vs port */
static bool port_hash_compare(void *candidat, void *searched)
{
	port_hash_item_t *port_item;
	unsigned short *port_searched;

	port_item = (port_hash_item_t*)candidat;
	port_searched = (unsigned short*)searched;

	if (*port_searched == port_item->port)
		return true;

	return false;
}

#ifdef CLS_DEBUG
/* print port item content */
static void port_print_item(void *data)
{
	port_hash_item_t *port_item = (port_hash_item_t*)data;

	cls_printf("    port %d rules: ", port_item->port);
	ba_print_set_bits(&port_item->rules);
}
#endif

/*  global array of 2x2 (per direction, per type) port hashs */
static hash_t port_hash_array[CLS_NET_DIR_TOTAL][PORT_TYPE_TOTAL] = {
	{
		{
			.name = "port_src_tcp_hash",
			.bits = PORT_HASH_NUM_OF_BITS,
		},
		{
			.name = "port_src_udp_hash",
			.bits = PORT_HASH_NUM_OF_BITS,
		},
	},
	{
		{
			.name = "port_dst_tcp_hash",
			.bits = PORT_HASH_NUM_OF_BITS,
		},
		{
			.name = "port_dst_udp_hash",
			.bits = PORT_HASH_NUM_OF_BITS,
		},
	}
};

/* global hash ops struct for port hash */
static hash_ops_t port_hash_ops;

/* port hash init function */
int port_cls_init(cls_hash_params_t *hash_params)
{
	int i, j;

	/* init the hash ops */
	port_hash_ops.comp = port_hash_compare;
	port_hash_ops.create_key = port_hash_genkey;
#ifdef CLS_DEBUG
	port_hash_ops.print = port_print_item;
#endif
	/* init the 3 uid hash array  ops */
	for (i=0; i<CLS_NET_DIR_TOTAL; i++)
		for (j=0; j<PORT_TYPE_TOTAL; j++)
			port_hash_array[i][j].hash_ops = &port_hash_ops;

	/* init the any rules */
	if (hash_params->any_offset == 0) {
		/* any rules was not prev allocated. lets allocate */
		port_any_rules = heap_calloc(sizeof(any_rules_t));
		if (!port_any_rules) {
			port_err("failed to allocate port any rules\n");
			return VSENTRY_ERROR;
		}

		for (i=0; i<CLS_NET_DIR_TOTAL; i++)
			for (j=0; j<PORT_TYPE_TOTAL; j++)
				port_any_rules->any_rules[i][j].empty = true;

		/* update the global database, will be used in the next boot */
		hash_params->any_offset = get_offset(port_any_rules);
	} else {
		/* restore prev allocated default rules */
		port_any_rules = get_pointer(hash_params->any_offset);
	}

	/* init the can hash table */
	if (hash_params->hash_offset == 0 || hash_params->bits != PORT_HASH_NUM_OF_BITS) {
		/* hash was not prev allocated. lets allocate.
		 * first we allocate memory to preserve the buckets offsets */
		port_buckets = heap_calloc(sizeof(port_buckets_array_t));
		if (!port_buckets) {
			port_err("failed to allocte port_buckets\n");
			return VSENTRY_ERROR;
		}

		/* allocate hashs */
		for (i=0; i<CLS_NET_DIR_TOTAL; i++) {
			for (j=0; j<PORT_TYPE_TOTAL; j++) {
				if (hash_create(&port_hash_array[i][j]) != VSENTRY_SUCCESS)
					return VSENTRY_ERROR;
				/* save the buckets offsets */
				port_buckets->buckets_offsets[i][j] = get_offset(port_hash_array[i][j].buckets);
			}
		}

		/* update the global database, will be used in the next boot */
		hash_params->bits = PORT_HASH_NUM_OF_BITS;
		hash_params->hash_offset = get_offset(port_buckets);
	} else {
		/* restore prev allocated hashs */
		port_buckets = get_pointer(hash_params->hash_offset);
		for (i=0; i<CLS_NET_DIR_TOTAL; i++) {
			for (j=0; j<PORT_TYPE_TOTAL; j++) {
				port_hash_array[i][j].buckets = get_pointer(port_buckets->buckets_offsets[i][j]);
				hash_set_ops(&port_hash_array[i][j]);
			}
		}
	}

	return VSENTRY_SUCCESS;
}

int  port_cls_add_rule(unsigned int rule, unsigned int port, unsigned int type, unsigned int dir)
{
	bit_array_t *arr = NULL;
	port_hash_item_t *port_item = NULL;
	port_type_e port_type;

	if (rule >= MAX_RULES || dir >= CLS_NET_DIR_TOTAL)
		return VSENTRY_ERROR;

	if (type == IPPROTO_TCP)
		port_type = PORT_TYPE_TCP;
	else if (type == IPPROTO_UDP)
		port_type = PORT_TYPE_UDP;
	else
		return VSENTRY_ERROR;

	if ((port != PORT_ANY) && (port > PORT_MAX))
		return VSENTRY_ERROR;

	port_dbg("add port rule port %u type %s dir %s\n", port, (type==IPPROTO_TCP)?"tcp":"udp",
			(dir==CLS_NET_DIR_SRC)?"src":"dst");

	if (port == PORT_ANY) {
		arr = &port_any_rules->any_rules[dir][port_type];
	} else {
		/* search if this data already exist */
		port_item = hash_get_data(&port_hash_array[dir][port_type], &port);
		if (!port_item) {
			/* allocate new port_item */
			port_item = heap_calloc(sizeof(port_hash_item_t));
			if (!port_item)
				return VSENTRY_ERROR;

			port_item->rules.empty = true;
			port_item->port = (unsigned short)port;
			hash_insert_data(&port_hash_array[dir][port_type], port_item);
			port_dbg("created new port rule port %u type %s dir %s\n", port,
					(type==IPPROTO_TCP)?"tcp":"udp",
					(dir==CLS_NET_DIR_SRC)?"src":"dst");
		}

		arr = &port_item->rules;
	}

	if (!ba_is_set(rule, arr)) {
		ba_set_bit(rule, arr);
		port_dbg("set bit %u on port rule port %u type %s dir %s\n", rule, port,
			(type==IPPROTO_TCP)?"tcp":"udp",
			(dir==CLS_NET_DIR_SRC)?"src":"dst");
	}

	return VSENTRY_SUCCESS;
}

int port_cls_del_rule(unsigned int rule, unsigned int port, unsigned int type, unsigned int dir)
{
	bit_array_t *arr = NULL;
	port_hash_item_t *port_item = NULL;
	port_type_e port_type;

	if (rule >= MAX_RULES || dir >= CLS_NET_DIR_TOTAL)
		return VSENTRY_ERROR;

	if (type == IPPROTO_TCP)
		port_type = PORT_TYPE_TCP;
	else if (type == IPPROTO_UDP)
		port_type = PORT_TYPE_UDP;
	else
		return VSENTRY_ERROR;

	if ((port != PORT_ANY) && (port > PORT_MAX))
		return VSENTRY_ERROR;

	if (port == PORT_ANY) {
		arr = &port_any_rules->any_rules[dir][port_type];
	} else {
		/* search if this data already exist */
		port_item = hash_get_data(&port_hash_array[dir][port_type], &port);
		if (!port_item)
			return VSENTRY_NONE_EXISTS;

		arr = &port_item->rules;
	}

	if (!ba_is_set(rule, arr))
		return VSENTRY_NONE_EXISTS;

	/* clear the rule bit */
	ba_clear_bit(rule, arr);

	/* if no more bit are set delete the entry */
	if (port_item && ba_is_empty(arr))
		hash_delete_data(&port_hash_array[dir][port_type], &port);

	return VSENTRY_SUCCESS;
}

int port_cls_search(ip_event_t *data, bit_array_t *verdict)
{
	bit_array_t *arr_any = NULL;
	port_hash_item_t *port_item = NULL;
	port_type_e port_type;

	if (data->ip_proto == IPPROTO_TCP)
		port_type = PORT_TYPE_TCP;
	else if (data->ip_proto == IPPROTO_UDP)
		port_type = PORT_TYPE_UDP;
	else
		return VSENTRY_ERROR;

	/* classify dport */
	arr_any = &port_any_rules->any_rules[CLS_NET_DIR_DST][port_type];
	port_item = hash_get_data(&port_hash_array[CLS_NET_DIR_DST][port_type], &data->dport);
	if (port_item) {
		if (!ba_is_empty(arr_any))
			/* if we have non-empty ANY rule , verdict calculation:
			 * verdict = verdict & (ANY | RULE)*/
			ba_and_or(verdict, verdict, &port_item->rules, arr_any);
		else
			/* no ANY rule, just AND verdict with specific rule */
			ba_and(verdict, verdict, &port_item->rules);
#ifdef ENABLE_LEARN
	} else if (cls_get_mode() == VSENTRY_MODE_LEARN) {
		/* in learn mode we dont want to get the default rule
		 * since we want to learn this event, so we clear the
		 * verdict bitmap to signal no match */
		ba_clear(verdict);

		return VSENTRY_SUCCESS;
#endif
	} else {
		/* no specific rule, just AND verdict with ANY rule */
		ba_and(verdict, verdict, arr_any);

		if (ba_is_empty(verdict))
			/* no need to continue. classification failed */
			return VSENTRY_SUCCESS;
	}

	/* classify sport */
	arr_any = &port_any_rules->any_rules[CLS_NET_DIR_SRC][port_type];
	port_item = hash_get_data(&port_hash_array[CLS_NET_DIR_SRC][port_type], &data->sport);
	if (port_item) {
		if (!ba_is_empty(arr_any))
			/* if we have non-empty ANY rule , verdict calculation:
			 * verdict = verdict & (ANY | RULE)*/
			ba_and_or(verdict, verdict, &port_item->rules, arr_any);
		else
			/* no ANY rule, just AND verdict with specific rule */
			ba_and(verdict, verdict, &port_item->rules);

		return VSENTRY_SUCCESS;
	}

	/* no specific rule, just AND verdict with ANY rule */
	ba_and(verdict, verdict, arr_any);

	return VSENTRY_SUCCESS;
}

typedef struct {
	int start;
	int end;
	int dir;
	int type;
} port_rules_limit_t;

static void check_port_rule(void *data, void* param)
{
	int i;
	port_hash_item_t *port_item = data;
	port_rules_limit_t* limit = param;

	for (i=limit->start; i<limit->end; i++) {
		if (ba_is_set(i, &port_item->rules))
			port_cls_del_rule(i, port_item->port, limit->type, limit->dir);
	}
}

void port_cls_clear_rules(int start, int end)
{
	int i, j;
	port_rules_limit_t limit = {
		.start = start,
		.end = end,
	};

	for (i=0; i<CLS_NET_DIR_TOTAL; i++) {
		limit.dir = i;

		for (j=0; j<PORT_TYPE_TOTAL; j++) {
			if (j == PORT_TYPE_TCP)
				limit.type = IPPROTO_TCP;
			else
				limit.type = IPPROTO_UDP;

			hash_walk(&port_hash_array[i][j], check_port_rule, &limit);
		}
	}
}

#ifdef CLS_DEBUG
void port_print_hash(void)
{
	int i, j;

	cls_printf("port db:\n");
	for (i=0; i<CLS_NET_DIR_TOTAL; i++) {
		for (j=0; j<PORT_TYPE_TOTAL; j++) {
			cls_printf("  hash %s\n", port_hash_array[i][j].name);
			hash_print(&port_hash_array[i][j]);
		}
	}

	cls_printf("  any src tcp: ");
	ba_print_set_bits(&port_any_rules->any_rules[CLS_NET_DIR_SRC][PORT_TYPE_TCP]);

	cls_printf("  any src udp: ");
	ba_print_set_bits(&port_any_rules->any_rules[CLS_NET_DIR_SRC][PORT_TYPE_UDP]);

	cls_printf("  any dst tcp: ");
	ba_print_set_bits(&port_any_rules->any_rules[CLS_NET_DIR_DST][PORT_TYPE_TCP]);

	cls_printf("  any dst udp: ");
	ba_print_set_bits(&port_any_rules->any_rules[CLS_NET_DIR_DST][PORT_TYPE_UDP]);

	cls_printf("\n");
}
#endif
