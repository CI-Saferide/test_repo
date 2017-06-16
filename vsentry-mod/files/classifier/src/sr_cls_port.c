#include "multiplexer.h"
#include "sal_linux.h"
#include "sal_bitops.h"
#include "sr_hash.h"
#include "sr_cls_port.h"

#define HT_PORT_SIZE 32
struct sr_hash_table_t *sr_cls_port_table;

int sr_cls_port_add_rule(SR_U32 port, SR_U32 rulenum);
int sr_cls_port_del_rule(SR_U32 port, SR_U32 rulenum);
struct sr_hash_ent_t *sr_cls_port_find(SR_U32 port);

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

void sr_cls_port_uninit(void)
{ 
	int i;
	struct sr_hash_ent_t* curr;
	struct sr_hash_ent_t* next;
	
	if (sr_cls_port_table != NULL) {
		sal_kernel_print_alert("DELETEING elements!\n");
		for(i = 0; i < HT_PORT_SIZE; i++) 
		{
			if (sr_cls_port_table->buckets[i].head != NULL){
				sal_kernel_print_alert("hash_index[%d] - DELETEING\n",i);
				curr = sr_cls_port_table->buckets[i].head;				
				while (curr != NULL){
					sal_kernel_print_alert("\t\tkey: %lu rule: %lu\n",curr->key,curr->rule);
					next = curr->next;
					SR_FREE(curr);
					curr= next;
				}
				//sal_kernel_print_alert("\n#############");
				//SR_FREE(sr_cls_port_table->buckets[i].head);
			}
		}
		
		if(sr_cls_port_table->buckets != NULL){
			sal_kernel_print_alert("DELETEING table->bucket\n");
			SR_FREE(sr_cls_port_table->buckets);
		}
		sal_kernel_print_alert("DELETEING table that orig size was: %lu\n",sr_cls_port_table->size);
		SR_FREE(sr_cls_port_table);
	}
}
int sr_cls_port_add_rule(SR_U32 port, SR_U32 rulenum)
{

	struct sr_hash_ent_t *ent;

	// TODO: Check for duplicated rules for same ports
	ent=sr_hash_lookup(sr_cls_port_table, port);
	if (!ent) {		
		ent = SR_ALLOC(sizeof(*ent)); // <-A MINE!!!
		if (!ent) {
			sal_kernel_print_alert("Error: Failed to allocate memory\n");
			return SR_ERROR;
		} else {
			ent->type = DST_PORT;
			ent->key = (SR_U32)port;
			ent->rule = (SR_U32)rulenum;
			sr_hash_insert(sr_cls_port_table,ent);
			return SR_SUCCESS;
		}	
	}	
	ent->rule = (SR_U32)rulenum;
	sal_kernel_print_alert("port: %lu exists rule: %lu\n",ent->key,ent->rule);
	
	return SR_SUCCESS;
}

void print_table(struct sr_hash_table_t *table)
{
	int i;
	struct sr_hash_ent_t* curr;
	struct sr_hash_ent_t* next;
	
	if (sr_cls_port_table != NULL) {
		sal_kernel_print_alert("Printing elements!\n");
		for(i = 0; i < HT_PORT_SIZE; i++) 
		{
			if (sr_cls_port_table->buckets[i].head != NULL){
				sal_kernel_print_alert("hash_index[%d]\n",i);
				curr = sr_cls_port_table->buckets[i].head;				
				while (curr != NULL){
					sal_kernel_print_alert("\t\tkey: %lu rule: %lu\n",curr->key,curr->rule);
					next = curr->next;
					curr= next;
				}
				//sal_kernel_print_alert("\n#############");
				//SR_FREE(sr_cls_port_table->buckets[i].head);
			}
		}
		
		if(sr_cls_port_table->buckets != NULL){
			sal_kernel_print_alert("Printing table->bucket\n");
		}
		sal_kernel_print_alert("Printing table that orig size was: %lu\n",sr_cls_port_table->size);
	}
	
}


struct sr_hash_ent_t *sr_cls_port_find(SR_U32 port)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_port_table, port);
	if (!ent) {
		sal_kernel_print_alert("Error:%lu Port not found\n",port);
		return NULL;
	}
	sal_kernel_print_alert("%lu Port found with rule:%lu\n",ent->key,ent->rule);
	return ent;
}

void sr_cls_port_ut(void)
{
	int i;
	for(i=0;i<HT_PORT_SIZE;i++)
			sr_cls_port_add_rule(i,i+i);
		
	for(i=0;i<HT_PORT_SIZE;i++)
		sr_cls_port_add_rule(1010+i*8,10+i*4);
	/*
	sr_cls_port_add_rule(22,10);
	sr_cls_port_add_rule(5566,4);
	sr_cls_port_add_rule(8080,8);
	sr_cls_port_add_rule(221,10);
	sr_cls_port_add_rule(5561,4);
	sr_cls_port_add_rule(8081,8);
	sr_cls_port_add_rule(8082,12);
	sr_cls_port_add_rule(8083,11);
	sr_cls_port_add_rule(809,10);
	sr_cls_port_add_rule(8019,2000);
	sr_cls_port_add_rule(8019,200);
	*/
	//sr_cls_port_add_rule(8083,11);
	//sr_cls_port_add_rule(809,10);
	//sr_cls_port_add_rule(8019,2000);

	
	//sr_cls_port_find(4444);
	//sr_cls_port_find(8080);
	
	print_table(sr_cls_port_table);

}
