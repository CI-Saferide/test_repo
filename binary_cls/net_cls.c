#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/vsentry/vsentry.h>
#include "net_cls.h"
#include "radix.h"
#include "heap.h"
#include "aux.h"

#ifdef NET_DEBUG
#define net_dbg cls_dbg
#define net_err cls_err
#else
#define net_dbg(...)
#define net_err(...)
#endif

/* the default rules data struct */
typedef struct __attribute__ ((packed, aligned(8))) {
	bit_array_t	any_rules[CLS_NET_DIR_TOTAL];
} any_rules_t;

/* the below struct will hold the radix trees offsets */
typedef struct __attribute__ ((packed, aligned(8))) {
	unsigned int 	radix_heads_offsets[CLS_NET_DIR_TOTAL];
} radix_tree_array_t;

static struct radix_tree *src_tree = NULL;
static struct radix_tree *dst_tree = NULL;
static any_rules_t *any_rules_array = NULL;

struct addrule_data {
	unsigned char   	add_rule; // o/w delete
	unsigned int 		rulenum;
	struct radix_node 	*node; // added/deleted rule's node, from which there is inheritance down
	struct radix_tree 	*tree;
};

int net_cls_init(cls_hash_params_t *hash_params)
{
	radix_tree_array_t *tree_array = NULL;

	/* init the any rules */
	if (hash_params->any_offset == 0) {
		/* any rules was not prev allocated. lets allocate */
		any_rules_array = heap_calloc(sizeof(any_rules_t));
		if (!any_rules_array) {
			net_err("failed to allocate net any_rules\n");
			return VSENTRY_ERROR;
		}

		/* update the global database, will be used in the next boot */
		hash_params->any_offset = get_offset(any_rules_array);
	} else {
		/* restore prev allocated default rules */
		any_rules_array = get_pointer(hash_params->any_offset);
	}

	/* init the radix trees */
	if (hash_params->hash_offset == 0) {
		/* not prev allocated. lets allocate.  */
		tree_array = heap_calloc(sizeof(radix_tree_array_t));
		if (!tree_array) {
			net_err("failed to allocate net tree_array\n");
			return VSENTRY_ERROR;
		}

		src_tree = heap_calloc(sizeof(src_tree));
		if (!src_tree) {
			net_err("failed to allocate net src_tree\n");
			return VSENTRY_ERROR;
		}

		dst_tree = heap_calloc(sizeof(dst_tree));
		if (!dst_tree) {
			net_err("failed to allocate net dst_tree\n");
			return VSENTRY_ERROR;
		}

		/* update the global database, will be used in the next boot */
		hash_params->hash_offset = get_offset(tree_array);
		tree_array->radix_heads_offsets[CLS_NET_DIR_SRC] = get_offset(src_tree);
		tree_array->radix_heads_offsets[CLS_NET_DIR_DST] = get_offset(dst_tree);
	} else {
		/* restore prev allocated trees */
		tree_array = get_pointer(hash_params->hash_offset);
		src_tree = get_pointer(tree_array->radix_heads_offsets[CLS_NET_DIR_SRC]);
		dst_tree = get_pointer(tree_array->radix_heads_offsets[CLS_NET_DIR_DST]);
	}

	if (!bin_rn_inithead(src_tree, (8 * offsetof(struct sockaddr_in, sin_addr)))) {
		net_err("failed to initialize src radix head\n");
		return VSENTRY_ERROR;
	}

	if (!bin_rn_inithead(dst_tree, (8 * offsetof(struct sockaddr_in, sin_addr)))) {
		net_err("failed to initialize dst radix head\n");
		return VSENTRY_ERROR;
	}

	return VSENTRY_SUCCESS;
}

static int walker_update_rule(struct radix_node *node, void *data)
{
	struct addrule_data *ad = (struct addrule_data *)data;
	unsigned char *kp, *my_kp, *my_mp;
	struct radix_node *del_node;

	if (node == ad->node) {
		if (ad->add_rule)
			ba_set_bit(ad->rulenum, &node->private.rules);
		else
			// delete
			ba_clear_bit(ad->rulenum, &node->private.rules);
	} else { // other leaf

		/* when a new leaf is added, its rule number is "passed down" to all leaves
		 * that match new leaf key & netmask.
		 * 2 conditions must be met:
		 *   1) node net mask is longer or equal to new leaf
		 *   2) node key & new leaf mask == new leaf key & new leaf mask
		 *
		 * same should be checked when we delete
		 */
		if (node->rn_bit <= ad->node->rn_bit) {
			kp = ((unsigned char *)(get_pointer(node->rn_key)) + 4);
			my_kp = ((unsigned char *)(get_pointer(ad->node->rn_key)) + 4);
			my_mp = ((unsigned char *)(get_pointer(ad->node->rn_mask)) + 4);

			if ((kp[0] & my_mp[0]) == (my_kp[0] & my_mp[0]) &&
					(kp[1] & my_mp[1]) == (my_kp[1] & my_mp[1]) &&
					(kp[2] & my_mp[2]) == (my_kp[2] & my_mp[2]) &&
					(kp[3] & my_mp[3]) == (my_kp[3] & my_mp[3])) {

				/*sr_debug("walker_update_rule: node 0x%llx, rule %d\n",
					(SR_U64)node & 0xFFFFFFF, (SR_U32)(long)ad->rulenum);*/

				if (ad->add_rule) {
					ba_set_bit(ad->rulenum, &node->private.rules);
				} else { // delete
					ba_clear_bit(ad->rulenum, &node->private.rules);
				}
			}
		}
	}

	// if we removed the last rule (cleared ba) from any leaf - we can now delete it
	if (ba_is_empty(&node->private.rules)) {
		del_node = bin_rn_delete(get_pointer(node->rn_key), get_pointer(node->rn_mask), ad->tree);
		if (!del_node) {
			net_err("failed to del ipv4, node not found!\n");
			return VSENTRY_ERROR;
		}
		heap_free(del_node);
	}

	return VSENTRY_SUCCESS;
}

int net_cls_add_rule(unsigned int rule, unsigned int addr, unsigned int netmask, unsigned int dir)
{
	struct radix_node *node = NULL;
	struct radix_node *treenodes = NULL;
	struct sockaddr_in *ip=NULL, *mask=NULL;
	struct addrule_data addrule_data;
	struct radix_tree *tree;
	short free_nodes = 0;

	if (rule >= MAX_RULES || dir >= CLS_NET_DIR_TOTAL)
		return VSENTRY_ERROR;

	if (netmask && addr) {
		if (dir == CLS_NET_DIR_SRC)
			tree = src_tree;
		else
			tree = dst_tree;

		treenodes = heap_calloc(2 * sizeof(struct radix_node) + sizeof(struct sockaddr_in));
		if (!treenodes)
			return -1;
		mask = heap_calloc(sizeof(struct sockaddr_in));
		if (!mask) {
			heap_free(treenodes);
			return -1;
		}
		ip = (struct sockaddr_in *)(treenodes + 2);

		/* before adding to tree, apply mask on given IP, to avoid user mistakes
		 * such as: IP = 0x12341234 with mask = 0xffff0000
		 * in this case we want: IP = 0x1234000 in tree
		 */
		ip->sin_family = AF_INET;
		ip->sin_addr.s_addr = (addr & netmask);
		//ip.sin_len = 32; // ????
		mask->sin_family = AF_INET;
		mask->sin_addr.s_addr = netmask;

		node = bin_rn_addroute((void*)ip, (void*)mask, tree, treenodes);
		if (node) { // new node, inherit from ancestors and duplicates

			/*  to inherit from ancestors:
			 * 	start at parent
			 * 	if parent's left != current node:
			 * 		go to parent's left
			 * 		if we reached a leaf:
			 * 			check if it is my ancestor and stop
			 * 		else:
			 * 			continue
			 * 	else:
			 * 		go to parent's parent
			 *  if we reached the root - stop anyway
			 *
			 * 	finding a single closest ancestor is enough, since it already inherited
			 * 	from all our previous (more far) ancestors
			 */
			struct radix_node *ptr = get_pointer(node->rn_parent);
			struct radix_node *left, *curr = node;
			unsigned char found_ancestor = 0;
			unsigned char *my_kp = (unsigned char *)get_pointer(node->rn_key) + 4;
			unsigned char *kp, *mp;
			//sal_kernel_print_alert("Checking ancestry for new node %p\n", node);
			//sal_kernel_print_info("find ancestor : node %p (b %d), parent %p (0x%llx, b %d), parent left 0x%llx, node left 0x%llx\n", node, node->rn_bit, ptr, node->rn_parent, ptr->rn_bit, ptr->rn_left, node->rn_left);

			while (ptr->rn_bit < 0) {
				// node is a duplicated node - ptr is also a leaf, go to its parent
				// may be more than one duplicate - so while is used
				//sal_kernel_print_info("duplicated node go to parent's parent: parent %p (0x%llx)\n", get_pointer(&ptr->rn_parent), ptr->rn_parent);
				ptr = get_pointer(ptr->rn_parent);
			}

			// while we have not found our ancestor or reached tree head
			while (!found_ancestor && !(ptr->rn_flags & RNF_ROOT)) {
				if (ptr->rn_left && ((left = get_pointer(ptr->rn_left)) != curr)) {
					curr = ptr;
					ptr = left;
					//sal_kernel_print_info("move left c %p (b %d) -> p %p (b %d)\n", curr, curr->rn_bit, ptr, ptr->rn_bit);

					if (ptr->rn_bit < 0) { // leaf
						// if this is a non empty leaf - check if ancestor
						if ((ptr->rn_bit != -33) && (ptr->rn_bit > node->rn_bit)) {
							kp = (unsigned char *)get_pointer(ptr->rn_key) + 4;
							mp = (unsigned char *)get_pointer(ptr->rn_mask) + 4;

							if ((kp[0] & mp[0]) == (my_kp[0] & mp[0]) &&
									(kp[1] & mp[1]) == (my_kp[1] & mp[1]) &&
									(kp[2] & mp[2]) == (my_kp[2] & mp[2]) &&
									(kp[3] & mp[3]) == (my_kp[3] & mp[3])) {
								// found closest ancestor
								found_ancestor = 1;

								/*sal_kernel_print_info("update ancestor %d.%d.%d.%d mask %d.%d.%d.%d (%p) -> node %p\n",
										kp[0], kp[1], kp[2], kp[3], mp[0], mp[1], mp[2], mp[3], ptr, node);*/

								ba_or(&node->private.rules, &node->private.rules, &ptr->private.rules);
							}
						}
						// move to leaf's parent before we continue left/up
						if (!found_ancestor) {
							curr = ptr;
							ptr = get_pointer(ptr->rn_parent);
							//sal_kernel_print_info("1 move up c %p (b %d), p %p  (b %d)\n", curr, curr->rn_bit, ptr, ptr->rn_bit);
						}
					} else if (ptr->rn_bit == 0) {
						// duplicated node - inherit from original node
						found_ancestor = 1; // end search
					}
				} else {
					curr = ptr;
					ptr = get_pointer(ptr->rn_parent);
					//sal_kernel_print_info("2 move up c %p (b %d), p %p  (b %d)\n", curr, curr->rn_bit, ptr, ptr->rn_bit);
				}
			}

			// if new node has a duplicated node - inherit from it as well
			if (node->rn_dupedkey) {
				//sal_kernel_print_info("inherit from duplicated node %llu, %p - > %p\n", node->rn_dupedkey, get_pointer(&node->rn_dupedkey), node);
				ptr = get_pointer(node->rn_dupedkey);
				ba_or(&node->private.rules, &node->private.rules, &ptr->private.rules);
			}
		}

		if (!node) { // failed to insert or node already exist
			//sal_kernel_print_info("failed to insert or node already exist\n");

			/* in case we add key & netmask that already exist - node will be NULL
			 * but we still need to set ba.
			 * check if node already exist - to update addrule_data */
			node = bin_rn_lookup((void*)ip, (void*)mask, tree);
			free_nodes = 1;
		}

		if (node) { // check again in case bin_rn_lookup() succeeded
			addrule_data.add_rule = 1;
			addrule_data.rulenum = rule;
			addrule_data.node = node;
			addrule_data.tree = tree;

			bin_rn_walktree_from(tree, ip, mask, walker_update_rule, (void*)&addrule_data);
		}
		if (free_nodes)
			heap_free(treenodes);

		heap_free(mask);

	} else if (netmask) {
		ba_set_bit(rule, &any_rules_array->any_rules[dir]);
	}

	return VSENTRY_SUCCESS;
}

int net_cls_del_rule(unsigned int rule, unsigned int addr, unsigned int netmask, unsigned int dir)
{
	struct radix_node *node = NULL;
	struct sockaddr_in *ip=NULL, *mask=NULL;
	struct addrule_data addrule_data;
	struct radix_tree *tree;

	if (rule >= MAX_RULES || dir >= CLS_NET_DIR_TOTAL)
		return VSENTRY_ERROR;

	if (netmask && addr) {
		if (dir == CLS_NET_DIR_SRC)
			tree = src_tree;
		else
			tree = dst_tree;

		ip = heap_calloc(sizeof(struct sockaddr_in));
		if (!ip)
			return -1;
		mask = heap_calloc(sizeof(struct sockaddr_in));
		if (!mask) {
			heap_free(ip);
			return -1;
		}

		/* before deleting from tree, apply mask on given IP, to avoid user mistakes
		 * such as: IP = 0x12341234 with mask = 0xffff0000
		 * in this case we want: IP = 0x1234000 in tree
		 */
		ip->sin_family = AF_INET;
		ip->sin_addr.s_addr = (addr & netmask);
		//ip.sin_len = 32; // ????
		mask->sin_family = AF_INET;
		mask->sin_addr.s_addr = netmask;

		node = bin_rn_lookup((void*)ip, (void*)mask, tree);
		if (!node) {
			net_dbg("failed to del ipv4 for rule %d, node not found!\n", rule);
			heap_free(ip);
			heap_free(mask);
			return VSENTRY_ERROR;
		}

		addrule_data.add_rule = 0; // delete
		addrule_data.rulenum = rule;
		addrule_data.node = node;
		addrule_data.tree = tree;

		// walker_update_rule() will clear the rule from ba and delete nodes if necessary (if ba is empty)
		bin_rn_walktree_from(tree, ip, mask, walker_update_rule, (void*)&addrule_data);
		heap_free(ip);
		heap_free(mask);

	} else if (netmask) {
		ba_clear_bit(rule, &any_rules_array->any_rules[dir]);
	}

	return VSENTRY_SUCCESS;
}

static int net_print_node(struct radix_node *node, void *data)
{
	unsigned short bit;
#ifdef NET_DEBUG
	char *addr, *mask;

	addr = ((char *)get_pointer(node->rn_u.rn_leaf.rn_Key) + 4);
	mask = ((char *)get_pointer(node->rn_u.rn_leaf.rn_Mask) + 4);
#endif
	cls_printf("    address %hhu.%hhu.%hhu.%hhu mask %hhu.%hhu.%hhu.%hhu. rules: ",
		*addr, *(addr+1), *(addr+2), *(addr+3),
		(unsigned char)*mask, (unsigned char)*(mask+1),
		(unsigned char)*(mask+2), (unsigned char)*(mask+3));

	ba_for_each_set_bit(bit, &node->private.rules)
		cls_printf("%d ", bit);

	cls_printf("\n");

	return VSENTRY_SUCCESS;
}

static int ip_cls_search_addr(unsigned int address, int dir, bit_array_t *verdict)
{
	struct radix_node *node = NULL;
	struct sockaddr_in ip;
	struct radix_tree *tree;
	bit_array_t *arr = NULL;

	if (dir == CLS_NET_DIR_SRC)
		tree = src_tree;
	else
		tree = dst_tree;

	memset(&ip, 0, sizeof(struct sockaddr_in));
	ip.sin_family = AF_INET;
	ip.sin_addr.s_addr = address;

	node = bin_rn_match((void*)&ip, tree);
	if (node) {
		arr = &node->private.rules;
	} else {
		if (cls_get_mode() == CLS_MODE_LEARN && dir == CLS_NET_DIR_DST) {
			/* in learn mode we dont want to get the default rule
			 * since we want to learn this event, so we clear the
			 * verdict bitmap to signal no match */
			ba_clear(verdict);

			return VSENTRY_SUCCESS;
		}

		arr = &any_rules_array->any_rules[dir];
	}

	ba_and(verdict, verdict, arr);

	return VSENTRY_SUCCESS;
}

int net_cls_search(ip_event_t *ev, bit_array_t *verdict)
{
	if (ev->daddr.v4addr == 0 || ev->saddr.v4addr == 0)
		return VSENTRY_SUCCESS;

	/* classify src addr */
	ip_cls_search_addr(htonl(ev->saddr.v4addr), CLS_NET_DIR_SRC, verdict);

	if (!ba_is_empty(verdict))
		/* classify dst addr */
		ip_cls_search_addr(htonl(ev->daddr.v4addr), CLS_NET_DIR_DST, verdict);

	return VSENTRY_SUCCESS;
}

void net_print_tree(void)
{
	unsigned short bit;

	cls_printf("ip db:\n");

	cls_printf("  src tree:\n");
	bin_rn_walktree(src_tree, net_print_node, NULL);
	cls_printf("  dst tree:\n");
	bin_rn_walktree(dst_tree, net_print_node, NULL);

	cls_printf("  any src: ");
	ba_for_each_set_bit(bit, &any_rules_array->any_rules[CLS_NET_DIR_SRC])
		cls_printf("%d ", bit);

	cls_printf("\n");

	cls_printf("  any dst: ");
	ba_for_each_set_bit(bit, &any_rules_array->any_rules[CLS_NET_DIR_DST])
		cls_printf("%d ", bit);

	cls_printf("\n");

	cls_printf("\n");
}

