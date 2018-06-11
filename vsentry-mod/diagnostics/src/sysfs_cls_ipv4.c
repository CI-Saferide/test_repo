/* file: sysfs_cls_ipv4.c
 * purpose: this file used as a getter/setter to the sysfs variables
*/

#ifdef SYSFS_SUPPORT

#include "cls_helper.h"
#include "sysfs_cls_ipv4.h"

struct sysfs_buf_list_node_t
{
	struct sysfs_buf_list_node_t *next;
	size_t len;
	unsigned char *buf;
};

static struct rule_database* sr_db;
static struct sr_hash_table_t *sr_cls_uid_table; // the uid table for NETWORK
static struct sr_hash_table_t *sr_cls_exec_file_table; // the binary table for NETWORK
static struct radix_head  *sr_cls_ipv4_table[2]; //index 0 SRC , 1 DST
static struct sr_hash_table_t *sr_cls_port_table[4]; // 0 - SR_SRC_TCP, 1 - SR_SRC_UDP, 2 - SR_DST_TCP, 3 - SR_DST_UDP
static struct sr_hash_table_t *sr_cls_protocol_table;
static struct sysfs_network_ent_t sysfs_network[SR_MAX_RULES];
static SR_U16 store_table_rule_num;
static struct sysfs_buf_list_node_t *buf_list_head;

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
							sal_sprintf(sysfs_network[rule].proto,"%s",((j == 0) || (j == 2)) ? "TCP":"UDP");
							
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

static size_t sysfs_write_ipv4_table_title(char __user *user_buf, size_t count, loff_t *ppos, size_t *used_count)
{
	size_t len = sal_sprintf(buf,
			"rule\t\tsrc_ip/mask\t\tdst_ip/mask\ts_port\td_port\tproto\tuid\tbinary\t\taction\n"
			"----------------------------------------------------------------------------------"
			"----------------------------\n");
	return write_to_user(user_buf, count, ppos, len, used_count);
}

static size_t store_table(char __user *user_buf, size_t count, loff_t *ppos, SR_U8 first_call)
{
	SR_U16 i;
	size_t rt, len, used_count = 0;
	
	if (first_call) {
		rt = sysfs_write_ipv4_table_title(user_buf, count, ppos, &used_count); // title
		if (rt)
			return rt;

		i = 0; // start from first rule
	} else {
		i = store_table_rule_num; // start from where we stopped
	}

	for (; i < SR_MAX_RULES; i++) {
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

		rt = write_to_user(user_buf, count, ppos, len, &used_count);
		if (rt)
			return rt;
	}
	
	*ppos = used_count;
	return used_count;
}

static size_t rn_printnode_single(struct radix_node *n, char __user *user_buf, size_t count, loff_t *ppos,
		size_t *used_count)
{
	size_t rt = 0, len = 0;
	bit_array matched_rules;
	SR_16 rule;

	if (n != NULL) {
		len += sal_sprintf(buf + len, "n = 0x%07llx, ", (SR_U64)n & 0xFFFFFFF);
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
			rt = write_to_user(user_buf, count, ppos, len, used_count);
			if (rt)
				return rt;

			// for non empty leaf - print duplicated (if exist)
			if ((n->rn_bit < 0) && (n->rn_bit != -33) && n->rn_dupedkey) {
				len = 0;
				len += sal_sprintf(buf + len, "duplicated node:\n");
				rt = write_to_user(user_buf, count, ppos, len, used_count);
				if (rt)
					return rt;

				rt = rn_printnode_single(n->rn_dupedkey, user_buf, count, ppos, used_count);
				if (rt)
					return rt;
			}
		}
	}
	return rt;
}

static size_t rn_printnode(struct radix_node *n, SR_U32 level, struct sysfs_buf_list_node_t **pknode,
		size_t count, size_t *used_count)
{
	size_t rt = 0;
	bit_array matched_rules;
	SR_16 rule;
	struct sysfs_buf_list_node_t *new_node;
	char *kbuf;

	if (n != NULL && pknode != NULL && *pknode != NULL) {

		if (*used_count + SR_MAX_PATH > count) {
			/* kbuf is out of space
			 * allocate new knode and add to list */
			new_node = SR_ZALLOC(sizeof(struct sysfs_buf_list_node_t));
			if (!new_node) {
				pr_warn("%s failed to allocate memory\n",__func__);
				return -ENOMEM;
			}
			new_node->buf = SR_ZALLOC(count);
			if (!new_node->buf) {
				pr_warn("%s failed to allocate memory\n",__func__);
				SR_FREE(new_node);
				return -ENOMEM;
			}
			// update current node length and reset
			(*pknode)->len = *used_count;
			*used_count = 0;
			// add new to list
			new_node->next = NULL;
			(*pknode)->next = new_node;
			// move to next
			*pknode = new_node;
		}
		kbuf = (*pknode)->buf;

		*used_count += sal_sprintf(kbuf + *used_count, "|level %d| n = 0x%07llx, ", level, (SR_U64)n & 0xFFFFFFF);
#ifdef DEBUG
		*used_count += sal_sprintf(kbuf + *used_count, "b = %s%d, f = %s|%s, ",
				n->rn_bit > 0 ? " " : "",
				n->rn_bit,
				n->rn_flags & RNF_NORMAL ? "N" : " ",
				n->rn_flags & RNF_ROOT ? "R" : " ");
#endif // DEBUG
		if (n == n->rn_parent) {
			*used_count += sal_sprintf(kbuf + *used_count, "p = NONE     ");
		} else {
			*used_count += sal_sprintf(kbuf + *used_count, "p = 0x%07llx", (SR_U64)n->rn_parent & 0xFFFFFFF);
		}
		if (n->rn_flags & RNF_ACTIVE) {
			if (n->rn_bit >= 0) {
				// node: print bmask, offset, left, right
				*used_count += sal_sprintf(kbuf + *used_count, ", bm = 0x%02x, o = %d, l = 0x%07llx, r = 0x%07llx",
						(SR_U8)n->rn_bmask,
						n->rn_offset,
						(SR_U64)n->rn_left & 0xFFFFFFF,
						(SR_U64)n->rn_right & 0xFFFFFFF);
			} else {
				// leaf: print dup, ip, rules
				if (n->rn_bit != -33) { // not empty
					*used_count += sal_sprintf(kbuf + *used_count, ", ip = %d.%d.%d.%d/%lu",
							*((SR_U8 *)(n->rn_key + 4)),
							*((SR_U8 *)(n->rn_key + 4) + 1),
							*((SR_U8 *)(n->rn_key + 4) + 2),
							*((SR_U8 *)(n->rn_key + 4)+ 3),
							abs(n->rn_bit + 33));

					memcpy(&matched_rules, &n->sr_private.rules, sizeof(matched_rules));
					*used_count += sal_sprintf(kbuf + *used_count, ", rules:");
					while ((rule = sal_ffs_and_clear_array (&matched_rules)) != -1) {
						*used_count += sal_sprintf(kbuf + *used_count, " %d", rule);
					}
				}
			}
			*used_count += sal_sprintf(kbuf + *used_count, "\n");

			// for non empty leaf - print duplicated (if exist)
			if ((n->rn_bit < 0) && (n->rn_bit != -33) && n->rn_dupedkey) {
				*used_count += sal_sprintf(kbuf + *used_count, "duplicated node:\n");
				rt = rn_printnode(n->rn_dupedkey, level, pknode, count, used_count); // same level
				if (rt)
					return rt;
			}

			// print left and right
			if (n->rn_bit >= 0) {
				rt = rn_printnode(n->rn_left, level + 1, pknode, count, used_count);
				if (rt)
					return rt;

				rt = rn_printnode(n->rn_right, level + 1, pknode, count, used_count);
				if (rt)
					return rt;
			}
		}
	}
	return rt;
}

static size_t rn_printtree(struct radix_head *h, char __user *user_buf, size_t count, loff_t *ppos, SR_U8 first_call)
{
	SR_U32 level = 0;
	size_t rt, used_count = 0;
	struct sysfs_buf_list_node_t *temp;

	if (h == NULL)
		return 0;

	if (first_call) {

		// allocate first knode
		buf_list_head = SR_ZALLOC(sizeof(struct sysfs_buf_list_node_t));
		if (!buf_list_head) {
			pr_warn("%s failed to allocate memory\n",__func__);
			return -ENOMEM;
		}
		buf_list_head->buf = SR_ZALLOC(count);
		if (!buf_list_head->buf) {
			pr_warn("%s failed to allocate memory\n",__func__);
			SR_FREE(buf_list_head);
			return -ENOMEM;
		}
		buf_list_head->next = NULL;

		// tree title
		used_count = sal_sprintf(buf_list_head->buf,
					"n: node pointer, p: parent pointer, bm: bit mask, o: byte offset, l: left pointer, r: right pointer\n"
					"---------------------------------------------------------------------------------------------------\n");

		// prepare print tree in knodes
		temp = buf_list_head;
		rt = rn_printnode(h->rnh_treetop, level, &temp, count, &used_count);
		if (rt) {
			// free all and return
			while (buf_list_head->next) {
				temp = buf_list_head->next;
				SR_FREE(buf_list_head->buf);
				SR_FREE(buf_list_head);
				buf_list_head = temp;
			}
			SR_FREE(buf_list_head->buf);
			SR_FREE(buf_list_head);
			return rt;
		}

		// update last knode length
		temp->len = used_count;
	}

	// start/continue coping from knodes to user_buf
	rt = simple_read_from_buffer(user_buf, count, ppos, buf_list_head->buf, buf_list_head->len);
	if ((rt != buf_list_head->len) || (*ppos != buf_list_head->len)) {
		pr_err("%s call to simple_read_from_buffer failed\n",__func__);
		// free all and return
		while (buf_list_head->next) {
			temp = buf_list_head->next;
			SR_FREE(buf_list_head->buf);
			SR_FREE(buf_list_head);
			buf_list_head = temp;
		}
		SR_FREE(buf_list_head->buf);
		SR_FREE(buf_list_head);
		return rt;
	}

	if (buf_list_head->next) {
		temp = buf_list_head->next;
		*ppos = 0; // so that func will be called again to continue
	} else { // done coping to user
		temp = NULL;
		*ppos = rt; // to avoid calling again
	}
	SR_FREE(buf_list_head->buf);
	SR_FREE(buf_list_head);
	buf_list_head = temp;
	return rt; // equal to buf_list_head->len, which has been freed
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

			sal_sprintf(sysfs_network[rule].src_ipv4,"%u.%u.%u.%u",
					(unsigned char)cp[0], (unsigned char)cp[1], (unsigned char)cp[2], (unsigned char)cp[3]);

		} else { // DST

			if (sysfs_network[rule].rule == rule && sysfs_network[rule].dst_flag == 1) {
				continue;
			}
			sysfs_network[rule].rule = rule;
			sysfs_network[rule].dst_flag = 1;
			sysfs_network[rule].d_port = get_port_for_rule(rule, *dir);
			sysfs_network[rule].dst_netmask_len = abs(node->rn_bit + 33);
			sal_sprintf(sysfs_network[rule].dst_ipv4,"%u.%u.%u.%u",
					(unsigned char)cp[0], (unsigned char)cp[1], (unsigned char)cp[2], (unsigned char)cp[3]);
		}

		sal_sprintf(sysfs_network[rule].proto,"%s","N/A");

		// putting some work for the UID...
		sysfs_network[rule].uid = get_uid_for_rule(sr_cls_uid_table,rule,UID_HASH_TABLE_SIZE,SR_NET_RULES);
		if (sysfs_network[rule].uid != -1) {
			if (sysfs_network[rule].uid == 0) {
				sal_sprintf(sysfs_network[rule].uid_buff, "%s", "ANY");
			} else
				sal_sprintf(sysfs_network[rule].uid_buff, "%d", sysfs_network[rule].uid);
		} else {
			sal_sprintf(sysfs_network[rule].uid_buff, "%s", "N/A");
		}

		// putting work for the BIN
		sysfs_network[rule].inode = get_exec_for_rule(sr_cls_exec_file_table,rule,EXEC_FILE_HASH_TABLE_SIZE,SR_NET_RULES);
		if (sysfs_network[rule].inode != -1) {
			if (sysfs_network[rule].inode == 0) {
				sal_sprintf(sysfs_network[rule].inode_buff, "%s", "ANY");
			} else
				sal_sprintf(sysfs_network[rule].inode_buff, "%u", sysfs_network[rule].inode);
		}

		sysfs_network[rule].action = sr_db->sr_rules_db[SR_NET_RULES][rule].actions;
		if (sysfs_network[rule].action & SR_CLS_ACTION_DROP) {
			sal_sprintf(sysfs_network[rule].actionstring, "Drop");
		} else if (sysfs_network[rule].action & SR_CLS_ACTION_ALLOW) {
			sal_sprintf(sysfs_network[rule].actionstring, "Allow");
		}
		if (sysfs_network[rule].action & SR_CLS_ACTION_LOG) {
			if (strlen(sysfs_network[rule].actionstring) == 0) {
				sal_sprintf(sysfs_network[rule].actionstring, "Log");
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

static size_t sr_cls_find_ipv4_print(SR_U32 addr, SR_8 dir, char __user *user_buf, size_t count,
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
		return rn_printnode_single(node, user_buf, count, ppos, used_count);
	} else {
		return 0;
	}
}

size_t dump_ipv4_table(char __user *user_buf, size_t count, loff_t *ppos, SR_U8 first_call)
{
	if (first_call)
		fetch_cls_ipv4();
	return store_table(user_buf, count, ppos, first_call);
}

size_t dump_ipv4_rule(SR_16 rule, char __user *user_buf, size_t count, loff_t *ppos)
{
	fetch_cls_ipv4();
	return store_rule(rule, user_buf, count, ppos);
}

size_t dump_ipv4_tree(SR_U8 dir, char __user *user_buf, size_t count, loff_t *ppos, SR_U8 first_call)
{
	return rn_printtree((dir==SR_DIR_SRC)?get_cls_src_ipv4_table():get_cls_dst_ipv4_table(),
			user_buf, count, ppos, first_call);
}

size_t dump_ipv4_ip(SR_32 ip, char __user *user_buf, size_t count, loff_t *ppos)
{
	size_t rt, len, used_count = 0;

	len = sal_sprintf(buf, "Source IP:\n----------\n");
	rt = write_to_user(user_buf, count, ppos, len, &used_count);
	if (rt)
		return rt;

	rt = sr_cls_find_ipv4_print(ip, SR_DIR_SRC, user_buf, count, ppos, &used_count);
	if (rt)
		return rt;

	len = sal_sprintf(buf, "Destination IP:\n---------------\n");
	rt = write_to_user(user_buf, count, ppos, len, &used_count);
	if (rt)
		return rt;

	rt = sr_cls_find_ipv4_print(ip, SR_DIR_DST, user_buf, count, ppos, &used_count);
	if (rt)
		return rt;

	*ppos = used_count;
	return used_count;
}

#endif /* SYSFS_SUPPORT */
