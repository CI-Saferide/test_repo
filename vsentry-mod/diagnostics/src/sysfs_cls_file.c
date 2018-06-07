/* file: sysfs_cls_file.c
 * purpose: this file used as a getter/setter to the sysfs variables
*/
#ifdef SYSFS_SUPPORT

#include "cls_helper.h"
#include "sysfs_cls_file.h"

static struct rule_database* sr_db;
static struct sr_hash_table_t *sr_cls_uid_table; // the uid table for file
static struct sr_hash_table_t *sr_cls_exec_file_table; // the binary table for file
static struct sr_hash_table_t *sr_cls_file_table; // the watched files table
static struct sysfs_file_ent_t sysfs_file[SR_MAX_RULES];
static SR_U16 store_table_rule_num;

#ifdef DEBUG
void sr_cls_print_rules(SR_U32 inode)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_file_table, inode);
	bit_array rules;
	SR_16 rule;

	memset(&rules, 0, sizeof(rules));
	sal_kernel_print_info("sr_cls_print_rules called for inode %d\n", (int)inode);
	if (!ent) {
		sal_kernel_print_err("Error: inode rule not found\n");
		return;
	}
	sal_or_self_op_arrays(&rules, &ent->rules);
	while ((rule = sal_ffs_and_clear_array (&rules)) != -1) {
		sal_kernel_print_info("Rule #%d\n", rule);
	}	
}

void print_table_files(struct sr_hash_table_t *table)
{
	SR_32 i;
	struct sr_hash_ent_t *curr, *next;
	
	if (table != NULL) {
		sal_kernel_print_info("Printing FILE INODE elements!\n");
		for(i = 0; i < EXEC_FILE_HASH_TABLE_SIZE; i++) {
			if (table->buckets[i].head != NULL){
				sal_kernel_print_info("hash_index[%d]\n",i);
				curr = table->buckets[i].head;
				while (curr != NULL){
					sal_kernel_print_info("\t\tINODE: %d\n",curr->key);
					sr_cls_print_rules(curr->key);
					next = curr->next;
					curr= next;
				}
			}
		}
		if(table->buckets != NULL){
			sal_kernel_print_info("Printed FILE INODE table->bucket\n");
		}
		sal_kernel_print_info("Printed FILE INODE table that orig size was: %u\n",table->size);
	}	
}
#endif

static void store_file_rules(SR_U32 inode)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_file_table, inode);
	bit_array rules;
	SR_16 rule;
	SR_8 perm_string[4] = {'-','-','-','\0'};

	sal_memset(&rules, 0, sizeof(rules));

	if (!ent) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"Error store_file_rules:%d INODE FILE rule not found\n",inode);
		return;
	}
	
	sal_or_self_op_arrays(&rules, &ent->rules);
	while ((rule = sal_ffs_and_clear_array (&rules)) != -1) {	
		
		sysfs_file[rule].rule = rule;
		sysfs_file[rule].inode = inode;
		sal_sprintf(sysfs_file[rule].inode_buff,"%u",inode);
		
		sysfs_file[rule].action = sr_db->sr_rules_db[SR_FILE_RULES][rule].actions;
		if (sysfs_file[rule].action & SR_CLS_ACTION_DROP) {
			sal_sprintf(sysfs_file[rule].actionstring, "Drop");
		} else if (sysfs_file[rule].action & SR_CLS_ACTION_ALLOW) {
			sal_sprintf(sysfs_file[rule].actionstring, "Allow");
		}
		if (sysfs_file[rule].action & SR_CLS_ACTION_LOG) {
			if (strlen(sysfs_file[rule].actionstring) == 0) {
				sal_sprintf(sysfs_file[rule].actionstring, "Log");
			} else {
				strcat(sysfs_file[rule].actionstring, "_log");
			}
		}

		//fetch the permission...
		sysfs_file[rule].file_ops = sr_db->sr_rules_db[SR_FILE_RULES][rule].file_ops;
		if (sysfs_file[rule].file_ops & SR_FILEOPS_READ)		{perm_string[0] = 'r';}
		if (sysfs_file[rule].file_ops & SR_FILEOPS_WRITE)		{perm_string[1] = 'w';}
		if (sysfs_file[rule].file_ops & SR_FILEOPS_EXEC)		{perm_string[2] = 'x';}
		sal_sprintf(sysfs_file[rule].perm_string,"%c%c%c",perm_string[0],perm_string[1],perm_string[2]);

		//putting some work for the UID...
		sysfs_file[rule].uid = get_uid_for_rule(sr_cls_uid_table,rule,UID_HASH_TABLE_SIZE,SR_FILE_RULES);
		if(sysfs_file[rule].uid == 0)
			sal_sprintf(sysfs_file[rule].uid_buff, "%s", "ANY");
		else
			sal_sprintf(sysfs_file[rule].uid_buff, "%d", sysfs_file[rule].uid);

		//putting work for the BIN
		sysfs_file[rule].inode_exe = get_exec_for_rule(sr_cls_exec_file_table,rule,EXEC_FILE_HASH_TABLE_SIZE,SR_FILE_RULES);
		if(sysfs_file[rule].inode_exe == 0)
			sal_sprintf(sysfs_file[rule].inode_exe_buff, "%s", "ANY");
		else
			sal_sprintf(sysfs_file[rule].inode_exe_buff, "%u", sysfs_file[rule].inode_exe);
	}
}

static void clone_cls_file_table(struct sr_hash_table_t *table)
{
	SR_32 i;
	bit_array ba_res;
	struct sr_hash_ent_t *curr, *next;
	SR_16 rule;
	SR_8 perm_string[4] = {'-','-','-','\0'};
	
	sal_memset(&ba_res, 0, sizeof(ba_res));
	sal_memset(sysfs_file, 0, sizeof(sysfs_file));
	
	if (table != NULL) {
		
		for(i = 0; i < EXEC_FILE_HASH_TABLE_SIZE; i++) {
			if (table->buckets[i].head != NULL){		
				curr = table->buckets[i].head;				
				while (curr != NULL){			
					store_file_rules(curr->key);
					next = curr->next;
					curr = next;
				}
			}
		}	
			
		sal_or_self_op_arrays(&ba_res,sr_cls_file_any());
		while ((rule = sal_ffs_and_clear_array (&ba_res)) != -1) {
				
			sysfs_file[rule].action = sr_db->sr_rules_db[SR_FILE_RULES][rule].actions;
			if (sysfs_file[rule].action & SR_CLS_ACTION_DROP) {
				sal_sprintf(sysfs_file[rule].actionstring, "Drop");
			} else if (sysfs_file[rule].action & SR_CLS_ACTION_ALLOW) {
				sprintf(sysfs_file[rule].actionstring, "Allow");
			}
			if (sysfs_file[rule].action & SR_CLS_ACTION_LOG) {
				if (strlen(sysfs_file[rule].actionstring) == 0) {
					sal_sprintf(sysfs_file[rule].actionstring, "Log");
				} else {
					strcat(sysfs_file[rule].actionstring, "_log");
				}
			}

			sysfs_file[rule].rule = rule;
			sysfs_file[rule].inode = 0;
			sal_sprintf(sysfs_file[rule].inode_buff,"%s","ANY");

			//fetch the permission...
			sysfs_file[rule].file_ops = sr_db->sr_rules_db[SR_FILE_RULES][rule].file_ops;
			if (sysfs_file[rule].file_ops & SR_FILEOPS_READ)		{perm_string[0] = 'r';}
			if (sysfs_file[rule].file_ops & SR_FILEOPS_WRITE)		{perm_string[1] = 'w';}
			if (sysfs_file[rule].file_ops & SR_FILEOPS_EXEC)		{perm_string[2] = 'x';}
			sal_sprintf(sysfs_file[rule].perm_string,"%c%c%c",perm_string[0],perm_string[1],perm_string[2]);
			//putting some work for the UID...
			sysfs_file[rule].uid = get_uid_for_rule(sr_cls_uid_table,rule,UID_HASH_TABLE_SIZE,SR_FILE_RULES);
			if(sysfs_file[rule].uid == 0)
				sal_sprintf(sysfs_file[rule].uid_buff, "%s", "ANY");
			else
				sal_sprintf(sysfs_file[rule].uid_buff, "%d", sysfs_file[rule].uid);

			//putting work for the BIN
			sysfs_file[rule].inode_exe = get_exec_for_rule(sr_cls_exec_file_table,rule,EXEC_FILE_HASH_TABLE_SIZE,SR_FILE_RULES);
			if(sysfs_file[rule].inode_exe == 0)
				sal_sprintf(sysfs_file[rule].inode_exe_buff, "%s", "ANY");
			else
				sal_sprintf(sysfs_file[rule].inode_exe_buff, "%u", sysfs_file[rule].inode_exe);
		}
	}
}	

static size_t sysfs_write_file_table_title(char __user *user_buf, size_t count, loff_t *ppos, size_t *used_count)
{
	size_t len = sal_sprintf(buf,"rule\tinode\t\tpermission\tuid\tbinary\t\taction\n"
			"----------------------------------------------------------------------\n");
	return write_to_user(user_buf, count, ppos, len, used_count);
}

static size_t store_table(struct sr_hash_table_t *table, char __user *user_buf, size_t count, loff_t *ppos,
		SR_U8 first_call)
{
	SR_U32 i;
	size_t rt, len, used_count = 0;

	if (first_call) {
		rt = sysfs_write_file_table_title(user_buf, count, ppos, &used_count); // title
		if (rt)
			return rt;

		i = 0; // start from first rule
	} else {
		i = store_table_rule_num; // start from where we stopped
	}
	
	for (; i < SR_MAX_RULES; i++) {
		if (sysfs_file[i].rule) {

			len = sal_sprintf(buf,"%d\t%s\t\t%s\t\t%s\t%s\t\t%s\n",
				sysfs_file[i].rule,
				sysfs_file[i].inode_buff,
				sysfs_file[i].perm_string,
				sysfs_file[i].uid_buff,
				sysfs_file[i].inode_exe_buff,
				sysfs_file[i].actionstring);
				
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

static size_t store_rule(struct sr_hash_table_t *table, SR_16 rule_find, char __user *user_buf, size_t count, loff_t *ppos)
{
	size_t rt, len, used_count = 0;

	rt = sysfs_write_file_table_title(user_buf, count, ppos, &used_count);
	if (rt)
		return rt;

	if (sysfs_file[rule_find].rule == rule_find) {
		len = sal_sprintf(buf,"%d\t%s\t\t%s\t\t%s\t%s\t\t%s\n",
			sysfs_file[rule_find].rule,
			sysfs_file[rule_find].inode_buff,
			sysfs_file[rule_find].perm_string,
			sysfs_file[rule_find].uid_buff,
			sysfs_file[rule_find].inode_exe_buff,
			sysfs_file[rule_find].actionstring);
				
		rt = write_to_user(user_buf, count, ppos, len, &used_count);
		if (rt)
			return rt;
	}

	*ppos = used_count;
	return used_count;
}

static void fetch_cls_file(void)
{
	sr_cls_uid_table = get_cls_uid_table(SR_FILE_RULES);
	sr_cls_exec_file_table = get_cls_exec_file_table();
	sr_cls_file_table = get_cls_file_table();
	sr_db = get_sr_rules_db();
#ifdef DEBUG
	print_table_files(sr_cls_file_table);
#endif

	clone_cls_file_table(sr_cls_file_table);
}

size_t dump_file_table(char __user *user_buf, size_t count, loff_t *ppos, SR_U8 first_call)
{
	if (first_call)
		fetch_cls_file();
	return store_table(sr_cls_file_table, user_buf, count, ppos, first_call);
}

size_t dump_file_rule(SR_16 rule,char __user *user_buf, size_t count, loff_t *ppos)
{
	fetch_cls_file();	
	return store_rule(sr_cls_file_table, rule, user_buf, count, ppos);
}
#endif /* SYSFS_SUPPORT */
