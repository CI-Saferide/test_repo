/* file: sysfs_cls_ipv4.c
 * purpose: this file used as a getter/setter to the sysfs variables
*/

#ifdef SYSFS_SUPPORT

#include "cls_helper.h"
#include "sysfs_cls_ipv4.h"

static unsigned char buf[SR_MAX_PATH];
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

/*
 * parameters:
 * count = user_buf size
 * ppos = start position in kernel_buf
 * len = number of Bytes to write
 * used_count = number of Bytes already written to user_buf
 */
static SR_U8 sysfs_write_to_user(char __user *user_buf, size_t count, loff_t *ppos,
		size_t len, size_t *used_count)
{
	size_t rt;

	*ppos = 0; // always read from start of buf
	if (*used_count + len > count) {
		pr_err("%s not enough space in user\n",__func__);
		return -EFBIG;
	}

	rt = simple_read_from_buffer(user_buf + *used_count, count, ppos, buf, len);
	if ((rt != len) || (*ppos != len))
		return rt;
	*used_count += len; // since it may be called several times

	return 0;
}

static SR_U8 sysfs_write_ipv4_table_title(char __user *user_buf, size_t count, loff_t *ppos,
		size_t *used_count)
{
	size_t len = sal_sprintf(buf,
			"rule\t\tsrc_ip/mask\t\tdst_ip/mask\ts_port\td_port\tproto\tuid\tbinary\t\taction\n"
			"----------------------------------------------------------------------------------"
			"----------------------------\n");
	return sysfs_write_to_user(user_buf, count, ppos, len, used_count);
}

static size_t store_table(char __user *user_buf, size_t count, loff_t *ppos)
{
	SR_U32 i;
	SR_U8 rt;
	size_t len, used_count = 0;
	
	rt = sysfs_write_ipv4_table_title(user_buf, count, ppos, &used_count);
	if (rt)
		return rt;

	for (i = 0; i < SR_MAX_RULES; i++) {
		if (sysfs_network[i].rule) {
			
			len = sal_sprintf(buf,"%d\t%015s/%d\t%015s/%d\t%d\t%d\t%s\t%s\t%s\t\t%s\n",
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

			rt = sysfs_write_to_user(user_buf, count, ppos, len, &used_count);
			if (rt)
				return rt;
		}
	}
	*ppos = used_count;
	return used_count;
}

static size_t store_rule(SR_16 rule_find, char __user *user_buf, size_t count, loff_t *ppos)
{
	SR_U8 rt;
	size_t len, used_count = 0;

	rt = sysfs_write_ipv4_table_title(user_buf, count, ppos, &used_count);
	if (rt)
		return rt;

	if (sysfs_network[rule_find].rule == rule_find) {

		len = sal_sprintf(buf,"%d\t%015s/%d\t%015s/%d\t%d\t%d\t%s\t%s\t%s\t\t%s\n",
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

		rt = sysfs_write_to_user(user_buf, count, ppos, len, &used_count);
		if (rt)
			return rt;
	}
	
	*ppos = used_count;
	return used_count;
}

static SR_U8 rn_printnode(struct radix_node *n, SR_U32 level, char __user *user_buf, size_t count,
		loff_t *ppos, size_t *used_count)
{
	SR_U8 rt = 0;
	size_t len  = 0;
	bit_array matched_rules;
	SR_16 rule;

	if (n != NULL) {
		if (level != -1) { // -1 is for a single node
			len += sal_sprintf(buf + len, "**lvl %d** ", level);
		}
		len += sal_sprintf(buf + len, "n = 0x%07llx, ", (SR_U64)n & 0xFFFFFFF);
#ifdef DEBUG
		len += sal_sprintf(buf + len, "b = %s%d, f = %s|%s, ",
				n->rn_bit > 0 ? " " : "",
				n->rn_bit,
				n->rn_flags & RNF_NORMAL ? "N" : " ",
				n->rn_flags & RNF_ROOT ? "R" : " ");
#endif // DEBUG
		if (n == n->rn_parent) {
			len += sal_sprintf(buf + len, "p = NONE     ");
		} else {
			len += sal_sprintf(buf + len, "p = 0x%07llx", (SR_U64)n->rn_parent & 0xFFFFFFF);
		}
		if (n->rn_flags & RNF_ACTIVE) {
			if (n->rn_bit >= 0) {
				// node: print bmask, offset, left, right
				len += sal_sprintf(buf + len, ", bm = 0x%02x, o = %d, l = 0x%07llx, r = 0x%07llx",
						(SR_U8)n->rn_bmask,
						n->rn_offset,
						(SR_U64)n->rn_left & 0xFFFFFFF,
						(SR_U64)n->rn_right & 0xFFFFFFF);
			} else {
				// leaf: print dup, ip, rules
				if (n->rn_bit != -33) { // not empty
					len += sal_sprintf(buf + len, ", ip = %d.%d.%d.%d/%lu",
							*((SR_U8 *)(n->rn_key + 4)),
							*((SR_U8 *)(n->rn_key + 4) + 1),
							*((SR_U8 *)(n->rn_key + 4) + 2),
							*((SR_U8 *)(n->rn_key + 4)+ 3),
							abs(n->rn_bit + 33));

					memcpy(&matched_rules, &n->sr_private.rules, sizeof(matched_rules));
					len += sal_sprintf(buf + len, ", rules:");
					while ((rule = sal_ffs_and_clear_array (&matched_rules)) != -1) {
						len += sal_sprintf(buf + len, " %d", rule);
					}
				}
			}
			len += sal_sprintf(buf + len, "\n");
			rt = sysfs_write_to_user(user_buf, count, ppos, len, used_count);
			if (rt)
				return rt;

			// for non empty leaf - print duplicated (if exist)
			if ((n->rn_bit < 0) && (n->rn_bit != -33) && n->rn_dupedkey) {
				len = 0;
				len += sal_sprintf(buf + len, "duplicated node:\n");
				rt = sysfs_write_to_user(user_buf, count, ppos, len, used_count);
				if (rt)
					return rt;

				rt = rn_printnode(n->rn_dupedkey, level, user_buf, count, ppos, used_count); // same level
				if (rt)
					return rt;
			}

			// print left and right
			if (n->rn_bit >= 0) {
				rt = rn_printnode(n->rn_left, level + 1, user_buf, count, ppos, used_count);
				if (rt)
					return rt;

				rt = rn_printnode(n->rn_right, level + 1, user_buf, count, ppos, used_count);
				if (rt)
					return rt;

			}
		}
	}
	return rt;
}

static size_t rn_printtree(struct radix_head *h, char __user *user_buf, size_t count, loff_t *ppos)
{
	SR_U8 rt;
	SR_U32 level = 0;
	size_t used_count = 0;

	if (h == NULL)
		return 0;
	rt = rn_printnode(h->rnh_treetop, level, user_buf, count, ppos, &used_count);
	if (rt)
		return rt;

	*ppos = used_count;
	return used_count;
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
		if (sysfs_network[rule].action & SR_CLS_ACTION_DROP) {
			sprintf(sysfs_network[rule].actionstring, "Drop");
		} else if (sysfs_network[rule].action & SR_CLS_ACTION_ALLOW) {
			sprintf(sysfs_network[rule].actionstring, "Allow");
		}
		if (sysfs_network[rule].action & SR_CLS_ACTION_LOG) {
			if (strlen(sysfs_network[rule].actionstring) == 0) {
				sprintf(sysfs_network[rule].actionstring, "Log");
			} else {
				strcat(sysfs_network[rule].actionstring, "_log");
			}
		}
	}
	return 0;
}

static void fetch_cls_ipv4(void)
{
	SR_U8 dir;

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
}

static SR_U8 sr_cls_find_ipv4_print(SR_U32 addr, SR_8 dir, char __user *user_buf, size_t count,
		loff_t *ppos, size_t *used_count)
{
	struct radix_node *node;
	struct sockaddr_in *ip;
	bit_array matched_rules;
	struct radix_head *tree_head=(dir==SR_DIR_SRC)?get_cls_src_ipv4_table():get_cls_dst_ipv4_table();

	memset(&matched_rules, 0, sizeof(matched_rules));
	ip = SR_ZALLOC(sizeof(struct sockaddr_in));
	if (!ip) {
		pr_warn("%s failed to allocate memory\n",__func__);
		return 0;
	}
	ip->sin_family = AF_INET;
	ip->sin_addr.s_addr = addr;

	node = rn_match((void*)ip, tree_head);
	SR_FREE(ip);
	if (node) {
		return rn_printnode(node, -1, user_buf, count, ppos, used_count);
	} else {
		return 0;
	}
}

size_t dump_ipv4_table(char __user *user_buf, size_t count, loff_t *ppos)
{
	fetch_cls_ipv4();
	return store_table(user_buf, count, ppos);
}

size_t dump_ipv4_rule(SR_16 rule, char __user *user_buf, size_t count, loff_t *ppos)
{
	fetch_cls_ipv4();
	return store_rule(rule, user_buf, count, ppos);
}

size_t dump_ipv4_tree(int dir, char __user *user_buf, size_t count, loff_t *ppos)
{
	return rn_printtree((dir==SR_DIR_SRC)?get_cls_src_ipv4_table():get_cls_dst_ipv4_table(),
			user_buf, count, ppos);
}

size_t dump_ipv4_ip(SR_32 ip, char __user *user_buf, size_t count, loff_t *ppos)
{
	size_t len, used_count = 0;
	SR_8 rt;

	len = sal_sprintf(buf, "Source IP:\n----------\n");
	rt = sysfs_write_to_user(user_buf, count, ppos, len, &used_count);
	if (rt)
		return rt;

	rt = sr_cls_find_ipv4_print(ip, SR_DIR_SRC, user_buf, count, ppos, &used_count);
	if (rt)
		return rt;

	len = sal_sprintf(buf, "Destination IP:\n---------------\n");
	rt = sysfs_write_to_user(user_buf, count, ppos, len, &used_count);
	if (rt)
		return rt;

	rt = sr_cls_find_ipv4_print(ip, SR_DIR_DST, user_buf, count, ppos, &used_count);
	if (rt)
		return rt;

	*ppos = used_count;
	return used_count;
}

#endif /* SYSFS_SUPPORT */
