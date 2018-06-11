/* file: debugfs_cls_can.c
 * purpose: this file used as a getter/setter to the debugfs variables
*/
#ifdef DEBUGFS_SUPPORT

#include "cls_helper.h"
#include "debugfs_cls_can.h"

static struct rule_database* sr_db;
static struct sr_hash_table_t *sr_cls_uid_table; // the uid table for CAN
static struct sr_hash_table_t *sr_cls_exec_file_table; // the binary table for CAN
static struct sr_hash_table_t *sr_cls_canid_table[2]; //index 0 INBOUND , 1 OUTBOUND
static struct debugfs_can_ent_t debugfs_canbus[SR_MAX_RULES];
static SR_U16 store_table_rule_num;

#ifdef DEBUG
void print_table_canid_debugfs(struct sr_hash_table_t *table,SR_8 dir)
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

static void store_canid_rules(SR_32 canid, SR_8 dir, bit_array *found_rules)
{
	bit_array rules;
	SR_16 rule;

	sal_memset(&rules, 0, sizeof(rules));
	sal_or_self_op_arrays(&rules, found_rules);
	while ((rule = sal_ffs_and_clear_array (&rules)) != -1) {

		if (strlen(debugfs_canbus[rule].dir) != 0) {
			// rule was already written for one direction but applies to
			sal_sprintf(debugfs_canbus[rule].dir,"%s", "BOTH");
		} else {
			// rule is written for the first time
			debugfs_canbus[rule].rule = rule;
			sal_sprintf(debugfs_canbus[rule].dir,"%s",(dir==SR_CAN_OUT)? "OUT" : "IN");

			if (canid != MSGID_ANY) {
				sal_sprintf(debugfs_canbus[rule].canid_buff,"0x%03x",canid);
				debugfs_canbus[rule].canid = canid;
			} else {
				sal_sprintf(debugfs_canbus[rule].canid_buff,"%s","ANY");
			}

			debugfs_canbus[rule].action = sr_db->sr_rules_db[SR_CAN_RULES][rule].actions;
			if (debugfs_canbus[rule].action & SR_CLS_ACTION_DROP) {
				sal_sprintf(debugfs_canbus[rule].actionstring, "Drop");
			} else if (debugfs_canbus[rule].action & SR_CLS_ACTION_ALLOW) {
				sal_sprintf(debugfs_canbus[rule].actionstring, "Allow");
			}
			if (debugfs_canbus[rule].action & SR_CLS_ACTION_LOG) {
				if (strlen(debugfs_canbus[rule].actionstring) == 0) {
					sal_sprintf(debugfs_canbus[rule].actionstring, "Log");
				} else {
					strcat(debugfs_canbus[rule].actionstring, "_log");
				}
			}

			//putting some work for the UID...
			debugfs_canbus[rule].uid = get_uid_for_rule(sr_cls_uid_table,rule,UID_HASH_TABLE_SIZE,SR_CAN_RULES);
			if(debugfs_canbus[rule].uid == 0)
				sal_sprintf(debugfs_canbus[rule].uid_buff, "%s", "ANY");
			else
				sal_sprintf(debugfs_canbus[rule].uid_buff, "%d", debugfs_canbus[rule].uid);

			//putting work for the BIN
			debugfs_canbus[rule].inode = get_exec_for_rule(sr_cls_exec_file_table,rule,EXEC_FILE_HASH_TABLE_SIZE,SR_CAN_RULES);
			if(debugfs_canbus[rule].inode == 0)
				sal_sprintf(debugfs_canbus[rule].inode_buff, "%s", "ANY");
			else
				sal_sprintf(debugfs_canbus[rule].inode_buff, "%d", debugfs_canbus[rule].inode);
		}
	}
}

static void lookup_and_store_canid_rules(SR_32 canid, SR_8 dir)
{
	struct sr_hash_ent_t *ent = sr_hash_lookup((dir==SR_CAN_OUT)?sr_cls_canid_table[SR_CAN_OUT]:sr_cls_canid_table[SR_CAN_IN], canid);

	if (!ent) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"Error lookup_and_store_canid_rules:%x CAN MsgID - %s rule not found\n",canid,(dir==SR_CAN_OUT)? "OUT" : "IN");
		return;
	}
	
	store_canid_rules(canid, dir, &ent->rules);
}

static void clone_cls_can_table(void)
{
	SR_32 i;
	struct sr_hash_ent_t *curr, *next;
	
	sal_memset(debugfs_canbus, 0, sizeof(debugfs_canbus));
	
	if (sr_cls_canid_table[0] != NULL && sr_cls_canid_table[1] != NULL) { // to verify we are after sr_cls_canid_init()

		// copy specific rules to debugfs
		for (i = 0; i < HT_canid_SIZE; i++) {
			curr = sr_cls_canid_table[SR_CAN_IN]->buckets[i].head;
			while (curr != NULL){

				lookup_and_store_canid_rules(curr->key, SR_CAN_IN);

				next = curr->next;
				curr= next;
			}
			curr = sr_cls_canid_table[SR_CAN_OUT]->buckets[i].head;
			while (curr != NULL){

				lookup_and_store_canid_rules(curr->key, SR_CAN_OUT);

				next = curr->next;
				curr= next;
			}
		}

		// copy "Any" rules to debugfs
		store_canid_rules(MSGID_ANY, SR_CAN_IN, src_cls_in_canid_any());
		store_canid_rules(MSGID_ANY, SR_CAN_OUT, src_cls_out_canid_any());
	}	
}

static size_t debugfs_write_can_table_title(char __user *user_buf, size_t count, loff_t *ppos, size_t *used_count)
{
	size_t len = sal_sprintf(buf ,"rule\tmsg_id\tdir\tuid\tbinary\taction\n"
			"----------------------------------------------\n");
	return write_to_user(user_buf, count, ppos, len, used_count);
}

static size_t store_table(char __user *user_buf, size_t count, loff_t *ppos, SR_U8 first_call)
{
	SR_U32 i;
	size_t rt, len, used_count = 0;
	
	if (first_call) {
		rt = debugfs_write_can_table_title(user_buf, count, ppos, &used_count); // title
		if (rt)
			return rt;

		i = 0; // start from first rule
	} else {
		i = store_table_rule_num; // start from where we stopped
	}

	for (; i < SR_MAX_RULES; i++) {
		if (debugfs_canbus[i].rule) {

			len = sal_sprintf(buf,"%d\t%s\t%s\t%s\t%s\t%s\n",
					debugfs_canbus[i].rule,
					debugfs_canbus[i].canid_buff,
					debugfs_canbus[i].dir,
					debugfs_canbus[i].uid_buff,
					debugfs_canbus[i].inode_buff,
					debugfs_canbus[i].actionstring);

			rt = write_to_user(user_buf, count, ppos, len, &used_count);
			if (rt) {
				// table has acceded 64k, save current rule number and continue when called again
				store_table_rule_num = i;
				return rt;
			}
		}
	}

	*ppos = used_count;
	return used_count;
}

static size_t store_rule(SR_16 rule_find, char __user *user_buf, size_t count, loff_t *ppos)
{
	size_t rt, len, used_count = 0;

	rt = debugfs_write_can_table_title(user_buf, count, ppos, &used_count);
	if (rt)
		return rt;

	if (debugfs_canbus[rule_find].rule == rule_find) {

		len = sal_sprintf(buf,"%d\t%s\t%s\t%s\t%s\t%s\n",
				debugfs_canbus[rule_find].rule,
				debugfs_canbus[rule_find].canid_buff,
				debugfs_canbus[rule_find].dir,
				debugfs_canbus[rule_find].uid_buff,
				debugfs_canbus[rule_find].inode_buff,
				debugfs_canbus[rule_find].actionstring);

		rt = write_to_user(user_buf, count, ppos, len, &used_count);
		if (rt)
			return rt;
	}

	*ppos = used_count;
	return used_count;
}

void fetch_cls_can(void)
{
	sr_cls_canid_table[SR_CAN_IN] = get_cls_in_can_table();
	sr_cls_canid_table[SR_CAN_OUT] = get_cls_out_can_table();
	sr_cls_uid_table = get_cls_uid_table(SR_CAN_RULES);
	sr_cls_exec_file_table = get_cls_exec_file_table();
	sr_db = get_sr_rules_db();
	
	clone_cls_can_table();
}

size_t dump_can_table(char __user *user_buf, size_t count, loff_t *ppos, SR_U8 first_call)
{
	if (first_call)
		fetch_cls_can();
	return store_table(user_buf, count, ppos, first_call);
}

size_t dump_can_rule(SR_16 rule,char __user *user_buf, size_t count, loff_t *ppos)
{
	fetch_cls_can();
	return store_rule(rule, user_buf, count, ppos);
}
#endif /* DEBUGFS_SUPPORT */
