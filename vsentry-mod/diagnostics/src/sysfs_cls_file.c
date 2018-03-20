/* file: sysfs_cls_file.c
 * purpose: this file used as a getter/setter to the sysfs variables
*/
#ifdef SYSFS_SUPPORT

#include "cls_helper.h"
#include "sysfs_cls_file.h"

static unsigned char* cls_file;
static unsigned char buffer[PAGE_SIZE];
static unsigned char buffer_RULE[SR_MAX_PATH];
static struct rule_database* sr_db;
static struct sr_hash_table_t *sr_cls_uid_table; // the uid table for file
static struct sr_hash_table_t *sr_cls_exec_file_table; // the binary table for file
static struct sr_hash_table_t *sr_cls_file_table; // the watched files table
static struct sysfs_file_ent_t sysfs_file[SR_MAX_RULES];

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
		sprintf(sysfs_file[rule].inode_buff,"%d",inode); 
		
		sysfs_file[rule].action = sr_db->sr_rules_db[SR_FILE_RULES][rule].actions;
		if (sysfs_file[rule].action & SR_CLS_ACTION_LOG) {
			if (sysfs_file[rule].action & SR_CLS_ACTION_DROP) {
				sprintf(sysfs_file[rule].actionstring, "Drop");
			} else if (sysfs_file[rule].action & SR_CLS_ACTION_ALLOW) {
				sprintf(sysfs_file[rule].actionstring, "Allow");
			} else {
				sprintf(sysfs_file[rule].actionstring, "log-only"); 
			}	
			
			//fetch the permission...
			sysfs_file[rule].file_ops = sr_db->sr_rules_db[SR_FILE_RULES][rule].file_ops;
			if (sysfs_file[rule].file_ops & SR_FILEOPS_READ)		{perm_string[0] = 'r';}
			if (sysfs_file[rule].file_ops & SR_FILEOPS_WRITE)		{perm_string[1] = 'w';}
			if (sysfs_file[rule].file_ops & SR_FILEOPS_EXEC)		{perm_string[2] = 'x';}
			sprintf(sysfs_file[rule].perm_string,"%c%c%c",perm_string[0],perm_string[1],perm_string[2]);
			
			//putting some work for the UID...
			sysfs_file[rule].uid = get_uid_for_rule(sr_cls_uid_table,rule,UID_HASH_TABLE_SIZE,SR_FILE_RULES);
			if(sysfs_file[rule].uid == 0)
				sprintf(sysfs_file[rule].uid_buff, "%s", "ANY");
			else
				sprintf(sysfs_file[rule].uid_buff, "%d", sysfs_file[rule].uid);
		
			//putting work for the BIN
			sysfs_file[rule].inode_exe = get_exec_for_rule(sr_cls_exec_file_table,rule,EXEC_FILE_HASH_TABLE_SIZE,SR_FILE_RULES);
			if(sysfs_file[rule].inode_exe == 0)
				sprintf(sysfs_file[rule].inode_exe_buff, "%s", "ANY");
			else
				sprintf(sysfs_file[rule].inode_exe_buff, "%d", sysfs_file[rule].inode_exe);
		}		
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
			if (sysfs_file[rule].action & SR_CLS_ACTION_LOG) {
				if (sysfs_file[rule].action & SR_CLS_ACTION_DROP) {
						sprintf(sysfs_file[rule].actionstring, "Drop");
					} else if (sysfs_file[rule].action & SR_CLS_ACTION_ALLOW) {
						sprintf(sysfs_file[rule].actionstring, "Allow");
					} else {
						sprintf(sysfs_file[rule].actionstring, "log-only"); 
					}			
					
					sysfs_file[rule].rule = rule;
					sysfs_file[rule].inode = 0;
					sprintf(sysfs_file[rule].inode_buff,"%s","ANY"); 
					
					//fetch the permission...
					sysfs_file[rule].file_ops = sr_db->sr_rules_db[SR_FILE_RULES][rule].file_ops;
					if (sysfs_file[rule].file_ops & SR_FILEOPS_READ)		{perm_string[0] = 'r';}
					if (sysfs_file[rule].file_ops & SR_FILEOPS_WRITE)		{perm_string[1] = 'w';}
					if (sysfs_file[rule].file_ops & SR_FILEOPS_EXEC)		{perm_string[2] = 'x';}
					sprintf(sysfs_file[rule].perm_string,"%c%c%c",perm_string[0],perm_string[1],perm_string[2]);
					//putting some work for the UID...
					sysfs_file[rule].uid = get_uid_for_rule(sr_cls_uid_table,rule,UID_HASH_TABLE_SIZE,SR_FILE_RULES);
					if(sysfs_file[rule].uid == 0)
						sprintf(sysfs_file[rule].uid_buff, "%s", "ANY");
					else
						sprintf(sysfs_file[rule].uid_buff, "%d", sysfs_file[rule].uid);
					
					//putting work for the BIN
					sysfs_file[rule].inode_exe = get_exec_for_rule(sr_cls_exec_file_table,rule,EXEC_FILE_HASH_TABLE_SIZE,SR_FILE_RULES);
					if(sysfs_file[rule].inode_exe == 0)
						sprintf(sysfs_file[rule].inode_exe_buff, "%s", "ANY");
					else
						sprintf(sysfs_file[rule].inode_exe_buff, "%d", sysfs_file[rule].inode_exe);
				}
			}
	}
}	


static void store_table(struct sr_hash_table_t *table)
{
	SR_U32 i;
	
	for(i = 0; i < SR_MAX_RULES; i++){
		if(sysfs_file[i].rule){
			sal_sprintf(buffer_RULE,"%d\t%s\t\t%s\t%s\t%s\t\t%s\n",
				sysfs_file[i].rule,
				sysfs_file[i].inode_buff,
				sysfs_file[i].perm_string,
				sysfs_file[i].uid_buff,
				sysfs_file[i].inode_exe_buff,
				sysfs_file[i].actionstring);
				
			strcat(buffer,buffer_RULE);	
		}
	}
	set_sysfs_file(buffer);
}

static void store_rule(struct sr_hash_table_t *table,SR_16 rule_find)
{
	if(sysfs_file[rule_find].rule == rule_find ){
		sal_sprintf(buffer_RULE,"%d\t%s\t\t%s\t%s\t%s\t\t%s\n",
			sysfs_file[rule_find].rule,
			sysfs_file[rule_find].inode_buff,
			sysfs_file[rule_find].perm_string,
			sysfs_file[rule_find].uid_buff,
			sysfs_file[rule_find].inode_exe_buff,
			sysfs_file[rule_find].actionstring);
				
		strcat(buffer,buffer_RULE);	
	}
	set_sysfs_file(buffer);	
}

static void fetch_cls_file(void)
{
	sal_memset(buffer, 0, PAGE_SIZE);

	sr_cls_uid_table = get_cls_uid_table(SR_FILE_RULES);
	sr_cls_exec_file_table = get_cls_exec_file_table();
	sr_cls_file_table = get_cls_file_table();
	sr_db = get_sr_rules_db();
#ifdef DEBUG
	print_table_files(sr_cls_file_table);
#endif

	clone_cls_file_table(sr_cls_file_table);
	sal_sprintf(buffer,"rule\tinode\t\tpermission\tuid\tbinary\t\taction\n--------------------------------------------------------------------\n");
}

void set_sysfs_file(unsigned char * buff)
{
	cls_file = buff;
}

unsigned char * get_sysfs_file (void)
{
	return cls_file;
}

void dump_file_table(void)
{
	fetch_cls_file();
	store_table(sr_cls_file_table);
}

void dump_file_rule(SR_16 rule)
{
	fetch_cls_file();	
	store_rule(sr_cls_file_table,rule);
}
#endif
