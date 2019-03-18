#ifndef __RADIX_H__
#define __RADIX_H__

#include "bitops.h"
#include "heap.h"

typedef char * caddr_t;
#define MIN(x, y) ((x < y) ? x : y)

#define radix_node_t 		unsigned int
#define radix_mask_head_t 	unsigned int
#define radix_mask_t    	unsigned int
#define radix_node_head_t 	unsigned int
#define radix_addr_t		unsigned int

/*
 * Radix search tree node layout.
 */

struct radix_node {
	radix_mask_t 	rn_mklist;	/* list of masks contained in subtree */
	radix_node_t 	rn_parent;	/* parent */
	short		rn_bit;		/* bit offset; -1-index(netmask) */
	char		rn_bmask;	/* node: mask for bit test*/
	unsigned char	rn_flags;	/* enumerated next */
#define RNF_NORMAL	1		/* leaf contains normal route */
#define RNF_ROOT	2		/* leaf is root leaf for tree */
#define RNF_ACTIVE	4		/* This node is alive (for rtfree) */
	union {
		struct {			/* leaf only data: */
			radix_addr_t	rn_Key;	/* object of search */
			radix_addr_t	rn_Mask;/* netmask, if present */
			radix_node_t 	rn_Dupedkey;
		} rn_leaf;

		struct { /* node only data: */
			int		rn_Off;	/* where to start compare */
			radix_node_t 	rn_L;   /* progeny */
			radix_node_t 	rn_R;   /* progeny */
		} rn_node;
	} rn_u;

	struct {
		bit_array_t rules;
	} private;

#ifdef RN_DEBUG
	int rn_info;
	radix_node_t rn_twin;
	radix_node_t rn_ybro;
#endif
};

#define	rn_dupedkey	rn_u.rn_leaf.rn_Dupedkey
#define	rn_key		rn_u.rn_leaf.rn_Key
#define	rn_mask		rn_u.rn_leaf.rn_Mask
#define	rn_offset	rn_u.rn_node.rn_Off
#define	rn_left		rn_u.rn_node.rn_L
#define	rn_right	rn_u.rn_node.rn_R

// todo add such defines to access the fields I've changed

/*
 * Annotations to tree concerning potential routes applying to subtrees.
 */

struct radix_mask {
	short	rm_bit;			/* bit offset; -1-index(netmask) */
	char	rm_unused;		/* cf. rn_bmask */
	int	rm_refs;		/* # of references to this struct */
	unsigned char rm_flags;		/* cf. rn_flags */
	radix_mask_t  rm_mklist;	/* more masks to try */
	union	{
		radix_addr_t rmu_mask;	/* the mask */
		radix_node_t rmu_leaf;	/* for normal routes */
	} rm_rmu;
};

#define	rm_mask rm_rmu.rmu_mask
#define	rm_leaf rm_rmu.rmu_leaf		/* extra field would make 32 bytes */

struct radix_tree {
	radix_node_head_t	head;
};

typedef int walktree_f_t(struct radix_node *, void *);
typedef struct radix_node *rn_matchaddr_f_t(void *v, struct radix_tree *t);
typedef struct radix_node *rn_addaddr_f_t(void *v, void *m, struct radix_tree *t, struct radix_node nodes[]);
typedef struct radix_node *rn_deladdr_f_t(void *v, void *m, struct radix_tree *t);
typedef struct radix_node *rn_lookup_f_t(void *v, void *m, struct radix_tree *t);
typedef int rn_walktree_t(struct radix_tree *t, walktree_f_t *f, void *w);
typedef int rn_walktree_from_t(struct radix_tree *t, void *a, void *m, walktree_f_t *f, void *w);
typedef void rn_close_t(struct radix_node *rn, struct radix_tree *t);

struct radix_head {
	radix_node_t 		rnh_treetop;
	radix_mask_head_t 	rnh_masks;	/* Storage for our masks */
	radix_addr_t 		rn_zeros;
	radix_addr_t 		rn_ones;
};

struct radix_node_head {
	struct radix_head 	rh;
	rn_matchaddr_f_t	*rnh_matchaddr;	/* longest match for sockaddr */
	rn_addaddr_f_t		*rnh_addaddr;	/* add based on sockaddr*/
	rn_deladdr_f_t		*rnh_deladdr;	/* remove based on sockaddr */
	rn_lookup_f_t		*rnh_lookup;	/* exact match for sockaddr */
	rn_walktree_t		*rnh_walktree;	/* traverse tree */
	rn_walktree_from_t	*rnh_walktree_from; /* traverse tree below a */
	rn_close_t		*rnh_close;	/*do something when the last ref drops*/
	struct	radix_node 	rnh_nodes[3];	/* empty tree for common case */
};

struct radix_mask_head {
	struct radix_head head;
	struct radix_node mask_nodes[3];
};

void bin_rn_inithead_internal(struct radix_head *rh, struct radix_node *base_nodes, int off);
int bin_rn_inithead(struct radix_tree *, int);
int bin_rn_detachhead(struct radix_tree *);
int bin_rn_refines(void *, void *);
int bin_rn_walktree_from(struct radix_tree *t, void *a, void *m, walktree_f_t *f, void *w);
int bin_rn_walktree(struct radix_tree *, walktree_f_t *, void *);
struct radix_node *bin_rn_addroute(void *, void *, struct radix_tree *, struct radix_node[2]);
struct radix_node *bin_rn_delete(void *, void *, struct radix_tree *);
struct radix_node *bin_rn_lookup (void *v_arg, void *m_arg, struct radix_tree *);
struct radix_node *bin_rn_match(void *, struct radix_tree *);

#endif /* __RADIX_H__ */
