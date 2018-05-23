/* file: sysfs_cls_ipv4.c
 * purpose: this file used as a getter/setter to the sysfs variables
*/

#ifdef SYSFS_SUPPORT

#include "cls_helper.h"
#include "sysfs_cls_ipv4.h"

static unsigned char* cls_ipv4;
static unsigned char buffer[PAGE_SIZE];
static unsigned char buffer_RULE[SR_MAX_PATH];
static struct rule_database* sr_db;
static struct sr_hash_table_t *sr_cls_uid_table; // the uid table for NETWORK
static struct sr_hash_table_t *sr_cls_exec_file_table; // the binary table for NETWORK
static struct radix_head  *sr_cls_ipv4_table[2]; //index 0 SRC , 1 DST
static struct sr_hash_table_t *sr_cls_port_table[4]; // 0 - SR_SRC_TCP, 1 - SR_SRC_UDP, 2 - SR_DST_TCP, 3 - SR_DST_UDP
static struct sr_hash_table_t *sr_cls_protocol_table;
static struct sysfs_network_ent_t sysfs_network[SR_MAX_RULES];

SR_32 get_port_for_rule(SR_16 rule, SR_U8 dir)
{
	SR_32 i,j;
	bit_array ba_res;
	struct sr_hash_ent_t *curr, *next;
	
	for (j=0; j<=3; j++) {
		if (sr_cls_port_table[j] != NULL) {
			for(i = 0; i < HT_PORT_SIZE; i++) {
				if (sr_cls_port_table[j]->buckets[i].head != NULL){
					curr = sr_cls_port_table[j]->buckets[i].head;				
					while (curr != NULL){
						if(sal_test_bit_array(rule,&curr->rules)){
							//according to the iteration the match was positive we know the proto
							sprintf(sysfs_network[rule].proto,"%s",((j == 0) || (j == 2)) ? "TCP":"UDP");
							
							if(dir == SR_DIR_SRC && (j == 1 || j == 0))
								return curr->key;
							if(dir == SR_DIR_DST && (j == 2 || j == 3))
								return curr->key;
						}
						next = curr->next;
						curr= next;
					}
				}
			}
		}
	}
	
	sal_or_self_op_arrays(&ba_res,(dir == SR_DIR_SRC)?src_cls_port_any_src():src_cls_port_any_dst());
	while ((rule = sal_ffs_and_clear_array (&ba_res)) != -1) {
		return 0;
	}	
	return -1;
}

int walktree_sysfs_print_rule(struct radix_node *node, void *data)
{
	SR_U8 *dir = (SR_U8 *)data;
	char *cp;
	bit_array matched_rules;
	SR_16 rule;

	memset(&matched_rules, 0, sizeof(matched_rules));
	memcpy(&matched_rules, &node->sr_private.rules, sizeof(matched_rules));

	while ((rule = sal_ffs_and_clear_array (&matched_rules)) != -1) {

		cp = (char *)node->rn_key + 4;

		// put some work to fetch the DST/SRC port OR any
		// need to check if its TCP or UDP <---- redundant to check again

		if (*dir == SR_DIR_SRC) {

			if (sysfs_network[rule].rule == rule && sysfs_network[rule].src_flag == 1) {
				continue;
			}
			sysfs_network[rule].rule = rule;
			sysfs_network[rule].src_flag = 1;
			sysfs_network[rule].src_netmask_len = abs(node->rn_bit + 33);
			sysfs_network[rule].s_port = get_port_for_rule(rule, *dir);

			sprintf(sysfs_network[rule].src_ipv4,"%u.%u.%u.%u",
					(unsigned char)cp[0], (unsigned char)cp[1], (unsigned char)cp[2], (unsigned char)cp[3]);

		} else { // DST

			if (sysfs_network[rule].rule == rule && sysfs_network[rule].dst_flag == 1) {
				continue;
			}
			sysfs_network[rule].rule = rule;
			sysfs_network[rule].dst_flag = 1;
			sysfs_network[rule].d_port = get_port_for_rule(rule, *dir);
			sysfs_network[rule].dst_netmask_len = abs(node->rn_bit + 33);
			sprintf(sysfs_network[rule].dst_ipv4,"%u.%u.%u.%u",
					(unsigned char)cp[0], (unsigned char)cp[1], (unsigned char)cp[2], (unsigned char)cp[3]);
		}

		sprintf(sysfs_network[rule].proto,"%s","N/A");

		// putting some work for the UID...
		sysfs_network[rule].uid = get_uid_for_rule(sr_cls_uid_table,rule,UID_HASH_TABLE_SIZE,SR_NET_RULES);
		if (sysfs_network[rule].uid != -1) {
			if (sysfs_network[rule].uid == 0) {
				sprintf(sysfs_network[rule].uid_buff, "%s", "ANY");
			} else
				sprintf(sysfs_network[rule].uid_buff, "%d", sysfs_network[rule].uid);
		} else {
			sprintf(sysfs_network[rule].uid_buff, "%s", "N/A");
		}

		// putting work for the BIN
		sysfs_network[rule].inode = get_exec_for_rule(sr_cls_exec_file_table,rule,EXEC_FILE_HASH_TABLE_SIZE,SR_NET_RULES);
		if (sysfs_network[rule].inode != -1) {
			if (sysfs_network[rule].inode == 0) {
				sprintf(sysfs_network[rule].inode_buff, "%s", "ANY");
			} else
				sprintf(sysfs_network[rule].inode_buff, "%u", sysfs_network[rule].inode);
		}

		sysfs_network[rule].action = sr_db->sr_rules_db[SR_NET_RULES][rule].actions;
		if (sysfs_network[rule].action & SR_CLS_ACTION_LOG) {
			if (sysfs_network[rule].action & SR_CLS_ACTION_DROP) {
				sprintf(sysfs_network[rule].actionstring, "Drop");
			} else if (sysfs_network[rule].action & SR_CLS_ACTION_ALLOW) {
				sprintf(sysfs_network[rule].actionstring, "Allow");
			} else {
				sprintf(sysfs_network[rule].actionstring, "log-only");
			}
		}
	}
	return 0;
}

static void store_table(struct radix_head** table)
{
	SR_U32 i;
	
	for(i = 0; i < SR_MAX_RULES; i++){
		if(sysfs_network[i].rule){
			
			sal_sprintf(buffer_RULE,"%d\t%015s/%d\t%015s/%d\t%d\t%d\t%s\t%s\t%s\t\t%s\n",
				sysfs_network[i].rule,
				sysfs_network[i].src_ipv4,
				sysfs_network[i].src_netmask_len,
				sysfs_network[i].dst_ipv4,
				sysfs_network[i].dst_netmask_len,
				sysfs_network[i].s_port,
				sysfs_network[i].d_port,
				sysfs_network[i].proto,
				sysfs_network[i].uid_buff,
				sysfs_network[i].inode_buff,
				sysfs_network[i].actionstring);
				
			strcat(buffer,buffer_RULE);
		}
	}
	set_sysfs_ipv4(buffer);
}

static void store_rule(struct radix_head** table,SR_16 rule_find)
{
		
	if(sysfs_network[rule_find].rule == rule_find ){
		sal_sprintf(buffer_RULE,"%d\t%015s/%d\t%015s/%d\t%d\t%d\t%s\t%s\t%s\t\t%s\n",
			sysfs_network[rule_find].rule,
			sysfs_network[rule_find].src_ipv4,
			sysfs_network[rule_find].src_netmask_len,
			sysfs_network[rule_find].dst_ipv4,
			sysfs_network[rule_find].dst_netmask_len,
			sysfs_network[rule_find].s_port,
			sysfs_network[rule_find].d_port,
			sysfs_network[rule_find].proto,
			sysfs_network[rule_find].uid_buff,
			sysfs_network[rule_find].inode_buff,
			sysfs_network[rule_find].actionstring);
				
		strcat(buffer,buffer_RULE);	
	}
	
	set_sysfs_ipv4(buffer);			
}

static void fetch_cls_ipv4(void)
{
	SR_U8 dir;

	sal_memset(buffer, 0, PAGE_SIZE);
	sal_memset(sysfs_network, 0, sizeof(sysfs_network));

	sr_cls_uid_table = get_cls_uid_table(SR_FILE_RULES);
	sr_cls_exec_file_table = get_cls_exec_file_table();
	sr_cls_ipv4_table[SR_DIR_SRC] = get_cls_src_ipv4_table();
	sr_cls_ipv4_table[SR_DIR_DST] = get_cls_dst_ipv4_table();	
	sr_db = get_sr_rules_db();

	sr_cls_port_table[SR_SRC_TCP] = get_cls_port_table(SR_SRC_TCP);
	sr_cls_port_table[SR_SRC_UDP] = get_cls_port_table(SR_SRC_UDP);
	sr_cls_port_table[SR_DST_TCP] = get_cls_port_table(SR_DST_TCP);
	sr_cls_port_table[SR_DST_UDP] = get_cls_port_table(SR_DST_UDP);
	sr_cls_protocol_table = get_cls_protocol_table();
	
	dir = SR_DIR_SRC;
	rn_walktree(sr_cls_ipv4_table[SR_DIR_SRC], walktree_sysfs_print_rule, &dir);
	dir = SR_DIR_DST;
	rn_walktree(sr_cls_ipv4_table[SR_DIR_DST], walktree_sysfs_print_rule, &dir);
	
	sal_sprintf(buffer,
		"rule\t\tsrc_ip/mask\t\tdst_ip/mask\ts_port\td_port\tproto\tuid\tbinary\t\taction\n"
		"----------------------------------------------------------------------------------"
		"----------------------------\n");
}

void set_sysfs_ipv4(unsigned char * buff)
{
	cls_ipv4 = buff;
}

unsigned char * get_sysfs_ipv4 (void)
{
	return cls_ipv4;
}

void dump_ipv4_table(void)
{
	fetch_cls_ipv4();
	store_table(sr_cls_ipv4_table);
}

void dump_ipv4_rule(SR_16 rule)
{
	fetch_cls_ipv4();
	store_rule(sr_cls_ipv4_table,rule);
}

#endif /* SYSFS_SUPPORT */
