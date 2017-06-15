#include "multiplexer.h"
#include "sal_linux.h"
#include "sal_bitops.h"
#include "sr_hash.h"
#include "sr_cls_port.h"

#define HT_PORT_SIZE 32
struct sr_hash_table_t *sr_cls_port_table;

void print_table(struct sr_hash_table_t *table)
{
	int i = 0;
	
	for(i = 0; i < HT_PORT_SIZE; i++) {
        if (sr_cls_port_table->buckets[i].head != NULL){
			sal_kernel_print_alert("KEY: %d rule: %d\n",
			sr_cls_port_table->buckets[i].head->key,
			sr_cls_port_table->buckets[i].head->rule);
			//((struct port_ent_t*)sr_cls_port_table->buckets[i].head)->rule);
        }
    }
	
}

int sr_cls_port_init(void)
{
	sr_cls_port_table = sr_hash_new_table(HT_PORT_SIZE);
	if (!sr_cls_port_table) {
		sal_kernel_print_alert("[%s]: Failed to allocate PORT table!\n", MODULE_NAME);
		return SR_ERROR;
	}
	sal_kernel_print_alert("[%s]: Successfully initialized PORT classifier!\n", MODULE_NAME);
	return SR_SUCCESS;
}
/*
struct port_ent_t {
	SR_U32 key; //the key is the PORT
	SR_U32 type;
	struct sr_hash_ent_t *next;
	SR_U16 port_num; //the key is the PORT
	SR_U32 rule;
	struct bit_array *bit_arr;
};
*/
int sr_cls_port_add_rule(SR_U32 port, SR_U32 rulenum)
{
	//struct port_ent_t *port_ent;
	struct sr_hash_ent_t *ent;
	
	//port_ent = SR_ALLOC(sizeof(*port_ent));
	//port_ent->type = 4;

	// TODO: Check for duplicated rules for same ports
	ent=sr_hash_lookup(sr_cls_port_table, port);
	if (!ent) {
		ent = SR_ALLOC(sizeof(*ent));
		if (!ent) {
			sal_kernel_print_alert("Error: Failed to allocate memory\n");
			return SR_ERROR;
		} else {
			ent->type = 4;
			ent->key = (SR_U32)port;
			ent->rule = (SR_U32)rulenum;
		}	
	}	
	//ent->rule = (SR_U32)rulenum;
	//sal_set_bit_array(rulenum, NULL);
	//if (ent->type == 4)
	//	port_ent = (struct port_ent_t*)ent;
		
	//sal_kernel_print_alert("Pre-insert port: %d rule: %d\n",(SR_U32)port_ent->key,(SR_U32)port_ent->rule);
	//sr_hash_insert(sr_cls_port_table,(struct sr_hash_ent_t*)port_ent);
	sr_hash_insert(sr_cls_port_table,(struct sr_hash_ent_t*)ent);
	//sal_kernel_print_alert("After insert port: %d rule: %d\n",(SR_U32)port_ent->key,(SR_U32)port_ent->rule);
	return SR_SUCCESS;
}

int sr_cls_port_del_rule(SR_U32 port, SR_U32 rulenum)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_port_table, port);
	if (!ent) {
		sal_kernel_print_alert("Error: Port rule not found\n");
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

int sr_cls_port_find(SR_U32 port)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_port_table, port);
	if (!ent) {
		sal_kernel_print_alert("Error:%d Port not found\n",port);
		return SR_ERROR;
	}
	sal_kernel_print_alert("%d Port found with rule:%d\n",(SR_U32)ent->key,(SR_U32)ent->rule);
	return SR_SUCCESS;
}


void sr_cls_port_ut(void)
{
	sr_cls_port_add_rule(22,10);
	sr_cls_port_add_rule(5566,4);
	sr_cls_port_add_rule(8080,8);
	sr_cls_port_add_rule(221,10);
	sr_cls_port_add_rule(5561,4);
	sr_cls_port_add_rule(8081,8);
	sr_cls_port_add_rule(8082,12);
	sr_cls_port_add_rule(8083,11);
	sr_cls_port_add_rule(809,10);
	sr_cls_port_add_rule(8019,20);
	sr_cls_port_add_rule(22,111);
	sr_cls_port_add_rule(22,112);
	
	sr_cls_port_find(4444);
	sr_cls_port_find(8080);
	
	print_table(sr_cls_port_table);
}

