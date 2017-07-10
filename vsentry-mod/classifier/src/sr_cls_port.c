#include "dispatcher.h"
#include "sal_bitops.h"
#include "sr_hash.h"
#include "sr_cls_port.h"

#include <linux/time.h> // for unit testing

#define HT_PORT_SIZE 32
struct sr_hash_table_t *sr_cls_port_table;

int sr_cls_port_init(void)
{
	sr_cls_port_table = sr_hash_new_table(HT_PORT_SIZE);
	if (!sr_cls_port_table) {
		sal_printf("[%s]: Failed to allocate PORT table!\n", MODULE_NAME);
		return SR_ERROR;
	}
	sal_printf("[%s]: Successfully initialized PORT classifier!\n", MODULE_NAME);
	
	return SR_SUCCESS;
}

void sr_cls_port_uninit(void)
{ 
	SR_32 i;
	struct sr_hash_ent_t *curr, *next;
	
	if (sr_cls_port_table != NULL) {
		sal_printf("DELETEING PORT elements!\n");
		for(i = 0; i < HT_PORT_SIZE; i++) {
			if (sr_cls_port_table->buckets[i].head != NULL){
				sal_printf("hash_index[%d] - DELETEING\n",i);
				curr = sr_cls_port_table->buckets[i].head;				
				while (curr != NULL){
					sal_printf("\t\tPORT: %u\n",curr->key);
					sr_cls_print_port_rules(curr->key);
					next = curr->next;
					SR_FREE(curr);
					curr= next;
				}
			}
		}
		
		if(sr_cls_port_table->buckets != NULL){
			sal_printf("DELETEING PORT table->bucket\n");
			SR_FREE(sr_cls_port_table->buckets);
		}
		sal_printf("DELETEING PORT table that orig size was: %u\n",sr_cls_port_table->size);
		SR_FREE(sr_cls_port_table);
	}
}

void sr_cls_port_remove(SR_U32 port)
{ 
	sr_hash_delete(sr_cls_port_table, port);
}

int sr_cls_port_add_rule(SR_U32 port, SR_U32 rulenum)
{
	struct sr_hash_ent_t *ent;
	
	ent=sr_hash_lookup(sr_cls_port_table, port);
	if (!ent) {		
		ent = SR_ZALLOC(sizeof(*ent)); // <-A MINE!!!
		if (!ent) {
			sal_printf("Error: Failed to allocate memory\n");
			return SR_ERROR;
		} else {
			ent->ent_type = DST_PORT;
			ent->key = (SR_U32)port;
			sr_hash_insert(sr_cls_port_table,ent);
		}	
	}	
	sal_set_bit_array(rulenum, &ent->rules);
	sal_printf("\t\trule# %u assigned to port: %u\n",rulenum,port);	
	return SR_SUCCESS;
}
int sr_cls_port_del_rule(SR_U32 port, SR_U32 rulenum)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_port_table, port);
	if (!ent) {
		sal_printf("Error can't del rule# %u on PORT:%u - rule not found\n",rulenum,port);
		return SR_ERROR;
	}
	sal_clear_bit_array(rulenum, &ent->rules);

	if (!ent->rules.summary) {
		sr_cls_port_remove(port);
	}
	sal_printf("\t\trule# %u removed from port: %u\n",rulenum,port);
	return SR_SUCCESS;
}

void print_table(struct sr_hash_table_t *table)
{
	SR_32 i;
	struct sr_hash_ent_t *curr, *next;
	
	if (sr_cls_port_table != NULL) {
		sal_printf("Printing PORT elements!\n");
		for(i = 0; i < HT_PORT_SIZE; i++) {
			if (sr_cls_port_table->buckets[i].head != NULL){
				sal_printf("hash_index[%d]\n",i);
				curr = sr_cls_port_table->buckets[i].head;				
				while (curr != NULL){
					sal_printf("\t\tport: %u\n",curr->key);
					sr_cls_print_port_rules(curr->key);
					next = curr->next;
					curr= next;
				}
			}
		}		
		if(sr_cls_port_table->buckets != NULL){
			sal_printf("Printed PORT table->bucket\n");
		}
		sal_printf("Printed PORT table that orig size was: %u\n",sr_cls_port_table->size);
	}	
}


struct sr_hash_ent_t *sr_cls_port_find(SR_U32 port)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_port_table, port);
	if (!ent) {
		sal_printf("Error:%u Port not found\n",port);
		return NULL;
	}
	//sal_printf("%lu Port found with rule:%lu\n",ent->key,ent->rule);
	return ent;
}

void sr_cls_print_port_rules(SR_U32 port)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_port_table, port);
	bit_array rules;
	SR_16 rule;

	sal_memset(&rules, 0, sizeof(rules));;
	if (!ent) {
		sal_printf("Error:%u port rule not found\n",port);
		return;
	}
	sal_or_self_op_arrays(&rules, &ent->rules);
	while ((rule = sal_ffs_and_clear_array (&rules)) != -1) {
		sal_printf("\t\t\tRule #%d\n", rule);
	}
	
}

int myRandom(int bottom, int top){ // for unit testing
	
	SR_U32 get_time;
	//int sec ,hr, min, tmp1,tmp2;
	SR_32 usec;
	struct timeval tv;

	do_gettimeofday(&tv);
	//get_time = tv.tv_sec;
	//sec = get_time % 60;
	//tmp1 = get_time / 60;
	//min = tmp1 % 60;
	//tmp2 = tmp1 / 60;
	//hr = tmp2 % 24;

	//printk("The time is hr:min:sec  ::  %d:%d:%dn",hr,min,sec);
	get_time = tv.tv_usec;
	usec = get_time % 9999;	
    return (usec % (top - bottom)) + bottom;
}

void sr_cls_port_ut(void)
{
/*	
	SR_32 i;
	SR_32 rand;
	for(i=0;i<HT_PORT_SIZE;i++){
		rand = myRandom(0, SR_MAX_PORT);
		sr_cls_port_add_rule(rand,myRandom(0, 4096));
	}*/
	print_table(sr_cls_port_table);

	sr_cls_port_add_rule(22,10);
	sr_cls_port_add_rule(5566,4);
	sr_cls_port_add_rule(8080,8);
	sr_cls_port_find(4444);
	sr_cls_port_find(8080);

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

	//print_table(sr_cls_port_table);
	
	sr_cls_port_find(4444);
	sr_cls_port_find(8080);
	
	sr_cls_port_add_rule(1000, 5);
	//print_table(sr_cls_port_table);
	sr_cls_port_add_rule(1000, 555);
	//print_table(sr_cls_port_table);
	sr_cls_port_add_rule(2000, 2000);
	//print_table(sr_cls_port_table);

	sr_cls_port_add_rule(9192, 7);
	//print_table(sr_cls_port_table);
	sr_cls_port_del_rule(1000, 5);
	//print_table(sr_cls_port_table);
	sr_cls_port_del_rule(1000, 555);
	//print_table(sr_cls_port_table);
	
	//print_table(sr_cls_port_table);
	sr_cls_port_add_rule(2000, 2000);	
	//print_table(sr_cls_port_table);
	sr_cls_port_del_rule(2000,2000);
	sr_cls_port_del_rule(9192, 7);
	//print_table(sr_cls_port_table);
	sal_printf("******************testing bucket collision******************\n");
	
	sr_cls_port_add_rule(8019,200);	
	sr_cls_port_add_rule(8083,11);
	sr_cls_port_add_rule(809,10);
	sr_cls_port_add_rule(8019,2000);
		
	sr_cls_port_add_rule(10, 7);
	sr_cls_port_add_rule(8202, 17);
	sr_cls_port_add_rule(16394, 27);
	sr_cls_port_add_rule(24586, 37);
	sr_cls_port_add_rule(32778, 47);
	//print_table(sr_cls_port_table);
	sr_cls_port_del_rule(16394, 27);
	print_table(sr_cls_port_table);

}