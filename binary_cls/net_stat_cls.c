#include <stddef.h>
#include <linux/vsentry/vsentry.h>
#include "net_stat_cls.h"
#include "hash.h"
#include "aux.h"
#include "heap.h"

#ifdef NET_STAT_DEBUG
#define net_stat_dbg cls_dbg
#define net_stat_err cls_err
#else
#define net_stat_dbg(...)
#define net_stat_err(...)
#endif

#define NET_STAT_HASH_NUM_OF_BITS 	10

/* hash item for NET_STAT */
typedef struct __attribute__ ((aligned(8))) {
	ip_event_t 		net_connection;
	unsigned long long	in_counter, out_counter;
	unsigned long long 	in_timestamp, out_timestamp;
} net_stat_hash_item_t;

/* the below struct will hold the hash buckets offsets on the persistent
 * database */
typedef struct __attribute__ ((aligned(8))) {
	unsigned int 	buckets_offsets;
} net_stat_buckets_array_t;

/* can hash buckets offset array */
static net_stat_buckets_array_t *net_stat_buckets = NULL;

/* hash key generate function for NET_STAT */
static unsigned int net_stat_hash_genkey(void *data, unsigned int number_of_bits)
{
	unsigned int key;
	net_stat_hash_item_t *net_stat_item = (net_stat_hash_item_t*)data;

	key = net_stat_item->net_connection.daddr.v4addr +
		net_stat_item->net_connection.dport +
		net_stat_item->net_connection.saddr.v4addr +
		net_stat_item->net_connection.sport +
		net_stat_item->net_connection.ip_proto;

	key = hash32(key, NET_STAT_HASH_NUM_OF_BITS);

	return key;
}

/* compare the hash item vs connection */
static bool net_stat_hash_compare(void *candidat, void *searched)
{
	net_stat_hash_item_t *net_stat_candidat;
	ip_event_t *con_searched;

	net_stat_candidat = (net_stat_hash_item_t*)candidat;
	con_searched = (ip_event_t*)searched;

	if (con_searched->dir == NET_DIR_IN) {
		if ((net_stat_candidat->net_connection.daddr.v4addr == con_searched->saddr.v4addr) &&
			(net_stat_candidat->net_connection.saddr.v4addr == con_searched->daddr.v4addr) &&
			(net_stat_candidat->net_connection.sport == con_searched->dport) &&
			(net_stat_candidat->net_connection.dport == con_searched->sport) &&
			(net_stat_candidat->net_connection.ip_proto == con_searched->ip_proto))
				return true;
	} else {
		if ((net_stat_candidat->net_connection.daddr.v4addr == con_searched->daddr.v4addr) &&
			(net_stat_candidat->net_connection.dport == con_searched->dport) &&
			(net_stat_candidat->net_connection.saddr.v4addr == con_searched->saddr.v4addr) &&
			(net_stat_candidat->net_connection.sport == con_searched->sport) &&
			(net_stat_candidat->net_connection.ip_proto == con_searched->ip_proto))
				return true;
	}

	return false;
}

/* print net_stat item content */
static void net_stat_print_item(void *data)
{
#ifdef NET_STAT_DEBUG
	net_stat_hash_item_t *net_stat_item = (net_stat_hash_item_t*)data;

	cls_printf("    src %d.%d.%d.%d sport %d dst %d.%d.%d.%d dport %d proto %d in_couner %llu out_couner %llu\n",
		(net_stat_item->net_connection.saddr.v4addr & 0xFF000000)>>24,
		(net_stat_item->net_connection.saddr.v4addr & 0xFF0000)>>16,
		(net_stat_item->net_connection.saddr.v4addr & 0xFF00)>>8,
		(net_stat_item->net_connection.saddr.v4addr & 0xFF),
		net_stat_item->net_connection.sport,
		(net_stat_item->net_connection.daddr.v4addr & 0xFF000000)>>24,
		(net_stat_item->net_connection.daddr.v4addr & 0xFF0000)>>16,
		(net_stat_item->net_connection.daddr.v4addr & 0xFF00)>>8,
		(net_stat_item->net_connection.daddr.v4addr & 0xFF),
		net_stat_item->net_connection.dport, net_stat_item->net_connection.ip_proto,
		net_stat_item->in_counter, net_stat_item->out_counter);
#endif
}

/*  global net_stat hash */
static hash_t net_stat_hash = {
	.name = "net_stat_hash",
	.bits = NET_STAT_HASH_NUM_OF_BITS,
};

/* global hash ops struct for net_stat hash */
static hash_ops_t net_stat_hash_ops;

/* can hash init function */
int net_stat_cls_init(cls_hash_params_t *hash_params)
{
	/* init the hash ops */
	net_stat_hash_ops.comp = net_stat_hash_compare;
	net_stat_hash_ops.create_key = net_stat_hash_genkey;
	net_stat_hash_ops.print = net_stat_print_item;

	/* init the net_stat hash ops */
	net_stat_hash.hash_ops = &net_stat_hash_ops;

	/* init the net_stat hash table */
	if (hash_params->hash_offset == 0 || hash_params->bits != NET_STAT_HASH_NUM_OF_BITS) {
		/* hash was not prev allocated. lets allocate.
		 * first we allocate memory to preserve the buckets offsets */
		net_stat_buckets = heap_calloc(sizeof(net_stat_buckets_array_t));
		if (!net_stat_buckets) {
			net_stat_err("failed to allocte net_stat_buckets\n");
			return VSENTRY_ERROR;
		}

		/* allocate hash */
		if (hash_create(&net_stat_hash) != VSENTRY_SUCCESS)
			return VSENTRY_ERROR;

		/* save the buckets offsets */
		net_stat_buckets->buckets_offsets = get_offset(net_stat_hash.buckets);

		/* update the global database, will be used in the next boot */
		hash_params->bits = NET_STAT_HASH_NUM_OF_BITS;
		hash_params->hash_offset = get_offset(net_stat_buckets);
	} else {
		/* restore prev allocated hashs */
		net_stat_buckets = get_pointer(hash_params->hash_offset);
		net_stat_hash.buckets = get_pointer(net_stat_buckets->buckets_offsets);
		hash_set_ops(&net_stat_hash);

		/* in this case (we are already allocated, we need to free
		 * any prev allocated memory, it is irrelevant */
		if (net_stat_hash.buckets->head_offset)
			hash_empty_data(&net_stat_hash);
	}

	return VSENTRY_SUCCESS;
}

int net_stat_cls_update_connection(vsentry_event_t *data)
{
	net_stat_hash_item_t *net_stat_item = NULL;

	if (data->ip_event.daddr.v4addr == 0 || data->ip_event.saddr.v4addr == 0)
		return VSENTRY_SUCCESS;

	/* search if this data already exist */
	net_stat_item = hash_get_data(&net_stat_hash, &data->ip_event);
	if (!net_stat_item) {
		/* allocate new can_item */
		net_stat_item = heap_calloc(sizeof(net_stat_hash_item_t));
		if (!net_stat_item)
			return VSENTRY_ERROR;

		memcpy(&net_stat_item->net_connection, data, sizeof(ip_event_t));
		net_stat_item->net_connection.len = 0;
		if (data->ip_event.dir == NET_DIR_IN) {
			net_stat_item->net_connection.daddr.v4addr = data->ip_event.saddr.v4addr;
			net_stat_item->net_connection.saddr.v4addr = data->ip_event.daddr.v4addr;
			net_stat_item->net_connection.dport = data->ip_event.sport;
			net_stat_item->net_connection.sport = data->ip_event.dport;
		}

		hash_insert_data(&net_stat_hash, net_stat_item);
	}

	if (data->ip_event.dir == NET_DIR_IN) {
		net_stat_item->in_counter += data->ip_event.len;
		net_stat_item->in_timestamp = data->ts;
	} else {
		net_stat_item->out_counter += data->ip_event.len;
		net_stat_item->out_timestamp = data->ts;
	}

	return VSENTRY_SUCCESS;
}

int net_stat_cls_del_connection(ip_event_t *data)
{
	net_stat_hash_item_t *net_stat_item = NULL;

	/* search if this data already exist */
	net_stat_item = hash_get_data(&net_stat_hash, data);
	if (!net_stat_item)
		return VSENTRY_NONE_EXISTS;

	return hash_delete_data(&net_stat_hash, data);
}

void net_stat_print_hash(void)
{
	cls_printf("netstat:\n");
	cls_printf("  hash %s\n", net_stat_hash.name);
	hash_print(&net_stat_hash);
	cls_printf("\n");
}
