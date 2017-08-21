#ifndef SR_HASH_H
#define SR_HASH_H

#include "sal_linux.h"
#include "sal_bitops.h"

enum policy_cls{
	SRC_IP,		//Source IP
	DST_IP,		//Destination IP
	SRC_PORT,	//Source port
	DST_PORT,	//Destination port	
	PROTOCOL,	//Protocol
	UID,		//User ID
	PROC_NAME,	//Process name
	FILE_NAME,	//File name
	FILE_DIR,	//File directory
	IO_OP,		//I/O operation type - read/write/open/close
	CAN_MID,	//CAN message ID
	TIME		//Time (implicit)
};

struct sr_hash_ent_t{
	SR_U32 key;
	SR_U32 type;
	struct sr_hash_ent_t *next;
	enum policy_cls ent_type;
	bit_array rules;
};

struct sr_hash_bucket_t{
	struct sr_hash_ent_t *head;
	// SR_U32 count; // might want this
	SR_RWLOCK bucket_lock;
};

struct sr_hash_table_t{
	SR_U32 size;
	SR_U32 count; // for sanity
	struct sr_hash_bucket_t *buckets;
};


struct sr_hash_table_t *sr_hash_new_table(int count);
int sr_hash_insert(struct sr_hash_table_t *table, void *ent);
void sr_hash_delete(struct sr_hash_table_t *table, SR_U32 key);
struct sr_hash_ent_t *sr_hash_lookup(struct sr_hash_table_t *table, SR_U32 key);
void sr_hash_free_table(struct sr_hash_table_t *table);
void sr_hash_print_table(struct sr_hash_table_t *table);
void sr_hash_empty_table(struct sr_hash_table_t *table);

#endif
