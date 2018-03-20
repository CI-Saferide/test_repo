/* file: sysfs_cls_can.c
 * purpose: this file used as a getter/setter to the sysfs variables
*/
#ifdef SYSFS_SUPPORT

#include "cls_helper.h"
#include "sysfs_cls_can.h"

static unsigned char* cls_can;
static unsigned char buffer[PAGE_SIZE];
static unsigned char buffer_RULE[SR_MAX_PATH];
static struct rule_database* sr_db;
static struct sr_hash_table_t *sr_cls_uid_table; // the uid table for CAN
static struct sr_hash_table_t *sr_cls_exec_file_table; // the binary table for CAN
static struct sr_hash_table_t *sr_cls_canid_table[2]; //index 0 INBOUND , 1 OUTBOUND
static struct sysfs_can_ent_t sysfs_canbus[SR_MAX_RULES];

#ifdef DEBUG
void print_table_canid_sysfs(struct sr_hash_table_t *table,SR_8 dir)
{
	SR_32 i;
	struct sr_hash_ent_t *curr, *next;
	
	if (table != NULL) {
		sal_kernel_print_info("Printing CAN MsgID elements!\n");	
		for(i = 0; i < HT_canid_SIZE; i++) {
			if (table->buckets[i].head != NULL){
				sal_kernel_print_info("hash_index[%d]\n",i);		
				curr = table->buckets[i].head;				
				while (curr != NULL){
					sal_kernel_print_info("\t\tCAN MsgID: %x dir: %s\n",curr->key,(dir==SR_CAN_OUT)? "OUT" : "IN");	
					sr_cls_print_canid_rules(curr->key,dir);
					next = curr->next;
					curr= next;
				}
			}
		}		
		if(table->buckets != NULL){
			sal_kernel_print_info("Printed CAN MsgID table->bucket\n");
		}
		sal_kernel_print_info("Printed CAN MsgID table that orig size was: %u\n",table->size);
	}	
}
#endif

static void store_canid_rules(SR_32 canid, SR_8 dir)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup((dir==SR_CAN_OUT)?sr_cls_canid_table[SR_CAN_OUT]:sr_cls_canid_table[SR_CAN_IN], canid);
	bit_array rules;
	SR_16 rule;

	sal_memset(&rules, 0, sizeof(rules));

	if (!ent) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"Error store_canid_rules:%x CAN MsgID - %s rule not found\n",canid,(dir==SR_CAN_OUT)? "OUT" : "IN");
		return;
	}
	
	sal_or_self_op_arrays(&rules, &ent->rules);
	while ((rule = sal_ffs_and_clear_array (&rules)) != -1) {
		
		sal_sprintf(sysfs_canbus[rule].canid_buff,"%03x",canid);
		sal_sprintf(sysfs_canbus[rule].dir,"%s",(dir==SR_CAN_OUT)? "OUT" : "IN");
		sysfs_canbus[rule].canid = canid;
		sysfs_canbus[rule].rule = rule;
		
		sysfs_canbus[rule].action = sr_db->sr_rules_db[SR_CAN_RULES][rule].actions;
		if (sysfs_canbus[rule].action & SR_CLS_ACTION_LOG) {
			if (sysfs_canbus[rule].action & SR_CLS_ACTION_DROP) {
				sprintf(sysfs_canbus[rule].actionstring, "Drop");
			} else if (sysfs_canbus[rule].action & SR_CLS_ACTION_ALLOW) {
				sprintf(sysfs_canbus[rule].actionstring, "Allow");
			} else {
				sprintf(sysfs_canbus[rule].actionstring, "log-only"); 
			}	
			
			//putting some work for the UID...
			sysfs_canbus[rule].uid = get_uid_for_rule(sr_cls_uid_table,rule,UID_HASH_TABLE_SIZE,SR_CAN_RULES);
			if(sysfs_canbus[rule].uid == 0)
				sprintf(sysfs_canbus[rule].uid_buff, "%s", "ANY");
			else
				sprintf(sysfs_canbus[rule].uid_buff, "%d", sysfs_canbus[rule].uid);
			
			//putting work for the BIN
			sysfs_canbus[rule].inode = get_exec_for_rule(sr_cls_exec_file_table,rule,EXEC_FILE_HASH_TABLE_SIZE,SR_CAN_RULES);
			if(sysfs_canbus[rule].inode == 0)
				sprintf(sysfs_canbus[rule].inode_buff, "%s", "ANY");
			else
				sprintf(sysfs_canbus[rule].inode_buff, "%d", sysfs_canbus[rule].inode);
		}		
	}
}

static void clone_cls_can_table(struct sr_hash_table_t **table)
{
	SR_32 i,j;
	SR_8 dir = 0; // to shut the warning...
	bit_array ba_res;
	struct sr_hash_ent_t *curr, *next;
	SR_16 rule;
	
	sal_memset(&ba_res, 0, sizeof(ba_res));
	
	if (table[0] != NULL && table[1] != NULL) {
		for (j=0; j<=1; j++) {
			for(i = 0; i < HT_canid_SIZE; i++) {
				if (table[j]->buckets[i].head != NULL){		
					curr = table[j]->buckets[i].head;				
					while (curr != NULL){
						
						if(!j)//if j is 0 this mean inbound
							dir = SR_CAN_IN;
						else
							dir = SR_CAN_OUT;
							
						store_canid_rules(curr->key,dir);
						
						next = curr->next;
						curr= next;
					}
				}
			}
			
			if(!j) //if j is 0 this mean inbound
				dir = SR_CAN_IN;
			else
				dir = SR_CAN_OUT;	
			
			sal_or_self_op_arrays(&ba_res, (dir==SR_CAN_OUT)?src_cls_out_canid_any():src_cls_in_canid_any());
			while ((rule = sal_ffs_and_clear_array (&ba_res)) != -1) {
				sysfs_canbus[rule].action = sr_db->sr_rules_db[SR_CAN_RULES][rule].actions;
				if (sysfs_canbus[rule].action & SR_CLS_ACTION_LOG) {
					if (sysfs_canbus[rule].action & SR_CLS_ACTION_DROP) {
						sprintf(sysfs_canbus[rule].actionstring, "Drop");
					} else if (sysfs_canbus[rule].action & SR_CLS_ACTION_ALLOW) {
						sprintf(sysfs_canbus[rule].actionstring, "Allow");
					} else {
						sprintf(sysfs_canbus[rule].actionstring, "log-only"); 
					}			
					
					sal_sprintf(sysfs_canbus[rule].dir,"%s",(dir==SR_CAN_OUT)? "OUT" : "IN");
					sysfs_canbus[rule].rule = rule;
					sal_sprintf(sysfs_canbus[rule].canid_buff,"%s","ANY");
					
					//putting some work for the UID...
					sysfs_canbus[rule].uid = get_uid_for_rule(sr_cls_uid_table,rule,UID_HASH_TABLE_SIZE,SR_CAN_RULES);
					if(sysfs_canbus[rule].uid == 0)
						sprintf(sysfs_canbus[rule].uid_buff, "%s", "ANY");
					else
						sprintf(sysfs_canbus[rule].uid_buff, "%d", sysfs_canbus[rule].uid);

					//putting work for the BIN
					sysfs_canbus[rule].inode = get_exec_for_rule(sr_cls_exec_file_table,rule,EXEC_FILE_HASH_TABLE_SIZE,SR_CAN_RULES);
					if(sysfs_canbus[rule].inode == 0)
						sprintf(sysfs_canbus[rule].inode_buff, "%s", "ANY");
					else
						sprintf(sysfs_canbus[rule].inode_buff, "%d",sysfs_canbus[rule].inode);
				}
			}
		}
	}	
}

static void store_table(void)
{
	SR_U32 i;
	
	for(i = 0; i < SR_MAX_RULES; i++){
		if(sysfs_canbus[i].rule){
			sal_sprintf(buffer_RULE,"%d\t%s\t%s\t%s\t%s\t%s\n",
				sysfs_canbus[i].rule,
				sysfs_canbus[i].canid_buff,
				sysfs_canbus[i].dir,
				sysfs_canbus[i].uid_buff,
				sysfs_canbus[i].inode_buff,
				sysfs_canbus[i].actionstring);
				
			strcat(buffer,buffer_RULE);	
		}
	}
	set_sysfs_can(buffer);
}

static void store_rule(SR_16 rule_find)
{
	if(sysfs_canbus[rule_find].rule == rule_find ){
		sal_sprintf(buffer_RULE,"%d\t%s\t%s\t%s\t%s\t%s\n",
			sysfs_canbus[rule_find].rule,
			sysfs_canbus[rule_find].canid_buff,
			sysfs_canbus[rule_find].dir,
			sysfs_canbus[rule_find].uid_buff,
			sysfs_canbus[rule_find].inode_buff,
			sysfs_canbus[rule_find].actionstring);
				
		strcat(buffer,buffer_RULE);	
	}
	set_sysfs_can(buffer);	
}

void fetch_cls_can(void)
{
	sal_memset(buffer, 0, PAGE_SIZE);
	sr_cls_canid_table[SR_CAN_IN] = get_cls_in_can_table();
	sr_cls_canid_table[SR_CAN_OUT] = get_cls_out_can_table();
	sr_cls_uid_table = get_cls_uid_table(SR_CAN_RULES);
	sr_cls_exec_file_table = get_cls_exec_file_table();
	sr_db = get_sr_rules_db();
	
	clone_cls_can_table(sr_cls_canid_table);
	sal_sprintf(buffer,"rule\tmsg_id\tdir\tuid\tbinary\taction\n------------------------------------------------\n");
}

void set_sysfs_can(unsigned char * buff)
{
	cls_can = buff;
}

unsigned char * get_sysfs_can (void)
{
	return cls_can;
}

void dump_can_table(void)
{
	fetch_cls_can();
	store_table();
}

void dump_can_rule(SR_16 rule)
{
	fetch_cls_can();
	store_rule(rule);
}
#endif
