#include "dispatcher.h"
#include "sal_bitops.h"
#include "sr_hash.h"
#include "sr_classifier.h"
#include "sr_cls_port.h"


//#include <linux/time.h> // for unit testing

#define HT_PORT_SIZE 32
struct sr_hash_table_t *sr_cls_dport_table[2]; // 0 - TCP, 1 - UDP
bit_array sr_cls_port_dst_any_rules;
struct sr_hash_table_t *sr_cls_sport_table[2]; // 0 - TCP, 1 - UDP
bit_array sr_cls_port_src_any_rules;

int sr_cls_port_init(void)
{
	int i;
	memset(&sr_cls_port_src_any_rules, 0, sizeof(bit_array));
	memset(&sr_cls_port_dst_any_rules, 0, sizeof(bit_array));

	for (i=0; i<=1; i++) {
		sr_cls_dport_table[i] = sr_hash_new_table(HT_PORT_SIZE);
		if (!sr_cls_dport_table[i]) {
			sal_printf("[%s]: Failed to allocate DPORT table!\n", MODULE_NAME);
			sr_cls_port_uninit();
			return SR_ERROR;
		}
		sr_cls_sport_table[i] = sr_hash_new_table(HT_PORT_SIZE);
		if (!sr_cls_sport_table[i]) {
			sal_printf("[%s]: Failed to allocate SPORT table!\n", MODULE_NAME);
			sr_cls_port_uninit();
			return SR_ERROR;
		}
	}
	sal_printf("[%s]: Successfully initialized PORT classifier!\n", MODULE_NAME);

	return SR_SUCCESS;
}

void sr_cls_port_empty_table(SR_BOOL is_lock)
{
	memset(&sr_cls_port_src_any_rules, 0, sizeof(bit_array));
	memset(&sr_cls_port_dst_any_rules, 0, sizeof(bit_array));
	sr_hash_empty_table(sr_cls_dport_table[0], is_lock);
	sr_hash_empty_table(sr_cls_dport_table[1], is_lock);
	sr_hash_empty_table(sr_cls_sport_table[0], is_lock);
	sr_hash_empty_table(sr_cls_dport_table[1], is_lock);
}

void sr_cls_port_uninit(void)
{ 
	SR_32 i, j;
	struct sr_hash_ent_t *curr, *next;
	
	for (j=0; j<=1; j++) {
		if (sr_cls_dport_table[j] != NULL) {
			for(i = 0; i < HT_PORT_SIZE; i++) {
				if (sr_cls_dport_table[j]->buckets[i].head != NULL){
					curr = sr_cls_dport_table[j]->buckets[i].head;				
					while (curr != NULL){
						next = curr->next;
						SR_FREE(curr);
						curr= next;
					}
				}
			}

			if(sr_cls_dport_table[j]->buckets != NULL){
				SR_FREE(sr_cls_dport_table[j]->buckets);
			}
			SR_FREE(sr_cls_dport_table[j]);
			sr_cls_dport_table[j] = NULL;
		}
		if (sr_cls_sport_table[j] != NULL) {
			for(i = 0; i < HT_PORT_SIZE; i++) {
				if (sr_cls_sport_table[j]->buckets[i].head != NULL){
					curr = sr_cls_sport_table[j]->buckets[i].head;				
					while (curr != NULL){
						next = curr->next;
						SR_FREE(curr);
						curr= next;
					}
				}
			}

			if(sr_cls_sport_table[j]->buckets != NULL){
				SR_FREE(sr_cls_sport_table[j]->buckets);
			}
			SR_FREE(sr_cls_sport_table[j]);
			sr_cls_sport_table[j] = NULL;
		}
	}
	sal_printf("[%s]: Successfully removed PORT classifier!\n", MODULE_NAME);
}

bit_array *src_cls_port_any_src(void)
{
        return &sr_cls_port_src_any_rules;
}
bit_array *src_cls_port_any_dst(void)
{
        return &sr_cls_port_dst_any_rules;
}


void sr_cls_port_remove(SR_U32 port, SR_8 dir, SR_8 proto)
{ 
	sr_hash_delete((dir==SR_DIR_DST)?sr_cls_dport_table[SR_PROTO_SELECTOR(proto)]:sr_cls_sport_table[SR_PROTO_SELECTOR(proto)], port);
}

int sr_cls_port_add_rule(SR_U32 port, SR_U32 rulenum, SR_8 dir, SR_8 proto)
{
	struct sr_hash_ent_t *ent;
	
	if (port != PORT_ANY) { 
		ent=sr_hash_lookup((dir==SR_DIR_DST)?sr_cls_dport_table[SR_PROTO_SELECTOR(proto)]:sr_cls_sport_table[SR_PROTO_SELECTOR(proto)], port);
		if (!ent) {		
			ent = SR_ZALLOC(sizeof(*ent)); // <-A MINE!!!
			if (!ent) {
				sal_printf("Error: Failed to allocate memory\n");
				return SR_ERROR;
			} else {
				ent->ent_type = DST_PORT;
				ent->key = (SR_U32)port;
				sr_hash_insert((dir==SR_DIR_DST)?sr_cls_dport_table[SR_PROTO_SELECTOR(proto)]:sr_cls_sport_table[SR_PROTO_SELECTOR(proto)],ent);
			}	
		}	
		sal_set_bit_array(rulenum, &ent->rules);
	} else {
		sal_set_bit_array(rulenum, (dir==SR_DIR_SRC)?&sr_cls_port_src_any_rules:&sr_cls_port_dst_any_rules);
	}
	return SR_SUCCESS;
}
int sr_cls_port_del_rule(SR_U32 port, SR_U32 rulenum, SR_8 dir, SR_8 proto)
{
	if (port != PORT_ANY) {
		struct sr_hash_ent_t *ent=sr_hash_lookup((dir==SR_DIR_DST)?sr_cls_dport_table[SR_PROTO_SELECTOR(proto)]:sr_cls_sport_table[SR_PROTO_SELECTOR(proto)], port);
		if (!ent) {
			sal_printf("Error can't del rule# %u on PORT:%u - rule not found\n",rulenum,port);
			return SR_ERROR;
		}
		sal_clear_bit_array(rulenum, &ent->rules);

		if (!ent->rules.summary) {
			sr_cls_port_remove(port, dir, proto);
		}
	} else { // "Any" rules
		sal_clear_bit_array(rulenum, (dir==SR_DIR_SRC)?&sr_cls_port_src_any_rules:&sr_cls_port_dst_any_rules);
	}
	return SR_SUCCESS;
}

void print_table(struct sr_hash_table_t *table)
{
	SR_32 i;
	struct sr_hash_ent_t *curr, *next;
	
	if (table != NULL) {
		sal_printf("Printing PORT elements!\n");
		for(i = 0; i < HT_PORT_SIZE; i++) {
			if (table->buckets[i].head != NULL){
				sal_printf("hash_index[%d]\n",i);
				curr = table->buckets[i].head;				
				while (curr != NULL){
					sal_printf("\t\tport: %u\n",curr->key);
					sr_cls_print_port_rules(curr->key, SR_DIR_DST, IPPROTO_TCP); // TODO: needed ?
					next = curr->next;
					curr= next;
				}
			}
		}		
		if(table->buckets != NULL){
			sal_printf("Printed PORT table->bucket\n");
		}
		sal_printf("Printed PORT table that orig size was: %u\n",table->size);
	}	
}


struct sr_hash_ent_t *sr_cls_port_find(SR_U32 port, SR_8 dir, SR_8 proto)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup((dir==SR_DIR_DST)?sr_cls_dport_table[SR_PROTO_SELECTOR(proto)]:sr_cls_sport_table[SR_PROTO_SELECTOR(proto)], port);
	if (!ent) {
		sal_printf("Error:%u Port not found\n",port);
		return NULL;
	}
	//sal_printf("%lu Port found with rule:%lu\n",ent->key,ent->rule);
	return ent;
}

void sr_cls_print_port_rules(SR_U32 port, SR_8 dir, SR_8 proto)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup((dir==SR_DIR_DST)?sr_cls_dport_table[SR_PROTO_SELECTOR(proto)]:sr_cls_sport_table[SR_PROTO_SELECTOR(proto)], port);
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

bit_array *sr_cls_match_port(SR_U32 port, SR_8 dir, SR_8 proto)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup((dir==SR_DIR_DST)?sr_cls_dport_table[SR_PROTO_SELECTOR(proto)]:sr_cls_sport_table[SR_PROTO_SELECTOR(proto)], port);

	if (!ent) {
		return NULL;
	}
	return(&ent->rules);
}

SR_8 sr_cls_port_msg_dispatch(struct sr_cls_port_msg *msg)
{
	int st;

	switch (msg->msg_type) {
		case SR_CLS_PORT_DEL_RULE:
			sal_kernel_print_alert("[PORT]Delete port %d,rulenum %d ,dir %d, proto %d\n", msg->port, msg->rulenum,msg->dir, msg->proto);
			if ((st = sr_cls_port_del_rule(msg->port, msg->rulenum,msg->dir, msg->proto)) != SR_SUCCESS) { 
			   return st;
			}
			if ((st = sr_cls_exec_inode_del_rule(SR_NET_RULES, msg->exec_inode, msg->rulenum)) != SR_SUCCESS) {
				return st;
			}
			return sr_cls_uid_del_rule(SR_NET_RULES, msg->uid, msg->rulenum);
			break;
		case SR_CLS_PORT_ADD_RULE:
			sal_kernel_print_alert("[PORT]Add port %d,rulenum %d ,dir %d, proto %d\n", msg->port, msg->rulenum,msg->dir, msg->proto);
			if ((st = sr_cls_port_add_rule(msg->port, msg->rulenum,msg->dir, msg->proto)) != SR_SUCCESS) { 
			   return st;
			}
			if ((st = sr_cls_exec_inode_add_rule(SR_NET_RULES, msg->exec_inode, msg->rulenum)) != SR_SUCCESS) { 
				return st;
			}
			return sr_cls_uid_add_rule(SR_NET_RULES, msg->uid, msg->rulenum);
			break;
		default:
			break;
	}
	return SR_SUCCESS;
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
		sr_cls_port_add_rule(rand,myRandom(0, 4096), SR_DIR_DST);
	}*/
	print_table(sr_cls_dport_table[SR_PROTO_SELECTOR(IPPROTO_TCP)]);

	sr_cls_port_add_rule(22,10, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_port_add_rule(5566,4, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_port_add_rule(8080,8, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_port_find(4444, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_port_find(8080, SR_DIR_DST, IPPROTO_TCP);

	sr_cls_port_add_rule(22,10, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_port_add_rule(5566,4, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_port_add_rule(8080,8, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_port_add_rule(221,10, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_port_add_rule(5561,4, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_port_add_rule(8081,8, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_port_add_rule(8082,12, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_port_add_rule(8083,11, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_port_add_rule(809,10, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_port_add_rule(8019,2000, SR_DIR_DST, IPPROTO_TCP);

	//print_table(sr_cls_dport_table);
	
	sr_cls_port_find(4444, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_port_find(8080, SR_DIR_DST, IPPROTO_TCP);
	
	sr_cls_port_add_rule(1000, 5, SR_DIR_DST, IPPROTO_TCP);
	//print_table(sr_cls_dport_table);
	sr_cls_port_add_rule(1000, 555, SR_DIR_DST, IPPROTO_TCP);
	//print_table(sr_cls_dport_table);
	sr_cls_port_add_rule(2000, 2000, SR_DIR_DST, IPPROTO_TCP);
	//print_table(sr_cls_dport_table);

	sr_cls_port_add_rule(9192, 7, SR_DIR_DST, IPPROTO_TCP);
	//print_table(sr_cls_dport_table);
	sr_cls_port_del_rule(1000, 5, SR_DIR_DST, IPPROTO_TCP);
	//print_table(sr_cls_dport_table);
	sr_cls_port_del_rule(1000, 555, SR_DIR_DST, IPPROTO_TCP);
	//print_table(sr_cls_dport_table);
	
	//print_table(sr_cls_dport_table);
	sr_cls_port_add_rule(2000, 2000, SR_DIR_DST, IPPROTO_TCP);	
	//print_table(sr_cls_dport_table);
	sr_cls_port_del_rule(2000,2000, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_port_del_rule(9192, 7, SR_DIR_DST, IPPROTO_TCP);
	//print_table(sr_cls_dport_table);
	sal_printf("******************testing bucket collision******************\n");
	
	sr_cls_port_add_rule(8019,200, SR_DIR_DST, IPPROTO_TCP);	
	sr_cls_port_add_rule(8083,11, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_port_add_rule(809,10, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_port_add_rule(8019,2000, SR_DIR_DST, IPPROTO_TCP);
		
	sr_cls_port_add_rule(10, 7, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_port_add_rule(8202, 17, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_port_add_rule(16394, 27, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_port_add_rule(24586, 37, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_port_add_rule(32778, 47, SR_DIR_DST, IPPROTO_TCP);
	//print_table(sr_cls_dport_table);
	sr_cls_port_del_rule(16394, 27, SR_DIR_DST, IPPROTO_TCP);
	print_table(sr_cls_dport_table[SR_PROTO_SELECTOR(IPPROTO_TCP)]);

}
