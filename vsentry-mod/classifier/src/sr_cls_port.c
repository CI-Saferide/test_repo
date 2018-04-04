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
			sal_kernel_print_err("[%s]: Failed to allocate DPORT table!\n", MODULE_NAME);
			sr_cls_port_uninit();
			return SR_ERROR;
		}
		sr_cls_sport_table[i] = sr_hash_new_table(HT_PORT_SIZE);
		if (!sr_cls_sport_table[i]) {
			sal_kernel_print_err("[%s]: Failed to allocate SPORT table!\n", MODULE_NAME);
			sr_cls_port_uninit();
			return SR_ERROR;
		}
	}
	sal_kernel_print_info("[%s]: Successfully initialized PORT classifier!\n", MODULE_NAME);

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
	sal_kernel_print_info("[%s]: Successfully removed PORT classifier!\n", MODULE_NAME);
}

struct sr_hash_table_t *get_cls_port_table(SR_U8 dir){
	
	switch(dir){
		case SR_SRC_TCP:
			return sr_cls_sport_table[0];
		case SR_SRC_UDP:
			return sr_cls_sport_table[1];
		case SR_DST_TCP:
			return sr_cls_dport_table[0];
		case SR_DST_UDP:
			return sr_cls_dport_table[1];
		default:
			sal_kernel_print_err("[%s]: Failed to GET PORT table!\n", MODULE_NAME);	
	}
	return NULL;
}

bit_array *src_cls_port_any_src(void)
{
        return &sr_cls_port_src_any_rules;
}
bit_array *src_cls_port_any_dst(void)
{
        return &sr_cls_port_dst_any_rules;
}


void sr_cls_port_remove(SR_U32 port, SR_8 dir, SR_U8 proto)
{ 
	sr_hash_delete((dir==SR_DIR_DST)?sr_cls_dport_table[SR_PROTO_SELECTOR(proto)]:sr_cls_sport_table[SR_PROTO_SELECTOR(proto)], port);
}

int sr_cls_port_add_rule(SR_U32 port, SR_U32 rulenum, SR_8 dir, SR_U8 proto)
{
	struct sr_hash_ent_t *ent;
	
	if (port != PORT_ANY) { 
		ent=sr_hash_lookup((dir==SR_DIR_DST)?sr_cls_dport_table[SR_PROTO_SELECTOR(proto)]:sr_cls_sport_table[SR_PROTO_SELECTOR(proto)], port);
		if (!ent) {		
			ent = SR_ZALLOC(sizeof(*ent)); // <-A MINE!!!
			if (!ent) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
								"reason=failed to allocate memory");
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
int sr_cls_port_del_rule(SR_U32 port, SR_U32 rulenum, SR_8 dir, SR_U8 proto)
{
	if (port != PORT_ANY) {
		struct sr_hash_ent_t *ent=sr_hash_lookup((dir==SR_DIR_DST)?sr_cls_dport_table[SR_PROTO_SELECTOR(proto)]:sr_cls_sport_table[SR_PROTO_SELECTOR(proto)], port);
		if (!ent) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
							"reason=cannot del rule %u on PORT %u - rule not found", rulenum, port);
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
		CEF_log_debug(SR_CEF_CID_SYSTEM, "info", SEVERITY_HIGH,
						"msg=printing PORT elements!");
		for(i = 0; i < HT_PORT_SIZE; i++) {
			if (table->buckets[i].head != NULL){
				CEF_log_debug(SR_CEF_CID_SYSTEM, "info", SEVERITY_HIGH,
								"msg=hash_index[%d]",i);
				curr = table->buckets[i].head;				
				while (curr != NULL){
					CEF_log_debug(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
									"msg=port %u",curr->key);
					sr_cls_print_port_rules(curr->key, SR_DIR_DST, IPPROTO_TCP); // TODO: needed ?
					next = curr->next;
					curr= next;
				}
			}
		}		
		if(table->buckets != NULL){
			CEF_log_debug(SR_CEF_CID_NETWORK, "info", SEVERITY_LOW,
							"msg=printed PORT table->bucket");
		}
		CEF_log_debug(SR_CEF_CID_NETWORK, "info", SEVERITY_LOW,
						"msg=printed PORT table that orig size was: %u",table->size);
	}	
}


struct sr_hash_ent_t *sr_cls_port_find(SR_U32 port, SR_8 dir, SR_U8 proto)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup((dir==SR_DIR_DST)?sr_cls_dport_table[SR_PROTO_SELECTOR(proto)]:sr_cls_sport_table[SR_PROTO_SELECTOR(proto)], port);
	if (!ent) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"reason=port %u not found",port);
		return NULL;
	}
	//CEF_log_event(SR_CEF_CID_NETWORK, "info", SEVERITY_LOW,"%lu Port found with rule:%lu\n",ent->key,ent->rule);
	return ent;
}

void sr_cls_print_port_rules(SR_U32 port, SR_8 dir, SR_U8 proto)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup((dir==SR_DIR_DST)?sr_cls_dport_table[SR_PROTO_SELECTOR(proto)]:sr_cls_sport_table[SR_PROTO_SELECTOR(proto)], port);
	bit_array rules;
	SR_16 rule;

	sal_memset(&rules, 0, sizeof(rules));;
	if (!ent) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"reason=port %u rule not found",port);
		return;
	}
	sal_or_self_op_arrays(&rules, &ent->rules);
	while ((rule = sal_ffs_and_clear_array (&rules)) != -1) {
		CEF_log_event(SR_CEF_CID_NETWORK, "info", SEVERITY_LOW,
						"msg=rule %d", rule);
	}
}

bit_array *sr_cls_match_port(SR_U32 port, SR_8 dir, SR_U8 proto)
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
			CEF_log_debug(SR_CEF_CID_NETWORK, "info", SEVERITY_LOW,
							"msg=[PORT]Delete port %d,rulenum %d ,dir %d, proto %d", msg->port, msg->rulenum,msg->dir, msg->proto);
			if ((st = sr_cls_port_del_rule(msg->port, msg->rulenum,msg->dir, msg->proto)) != SR_SUCCESS) { 
			   return st;
			}
			if ((st = sr_cls_exec_inode_del_rule(SR_NET_RULES, msg->exec_inode, msg->rulenum)) != SR_SUCCESS) {
				return st;
			}
			return sr_cls_uid_del_rule(SR_NET_RULES, msg->uid, msg->rulenum);
			break;
		case SR_CLS_PORT_ADD_RULE:
			CEF_log_debug(SR_CEF_CID_NETWORK, "info", SEVERITY_LOW,
							"msg=[PORT]Add port %d,rulenum %d ,dir %d, proto %d", msg->port, msg->rulenum,msg->dir, msg->proto);
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
