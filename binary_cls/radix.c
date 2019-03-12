/*-
 * Copyright (c) 1988, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)radix.c	8.5 (Berkeley) 5/19/95
 * $FreeBSD$
 */

/*
 * Routines to build and maintain radix trees for routing lookups.
 */
#include <linux/in.h>
#include "radix.h"
#include "aux.h"

#ifdef RADIX_DEBUG
#define radix_dbg cls_dbg
#define radix_err cls_err
#else
#define radix_dbg(...)
#define radix_err(...)
#endif

#define R_Malloc(p, t, n) (p = (t) heap_alloc((unsigned int)(n)))
#define R_Zalloc(p, t, n) (p = (t) heap_calloc((unsigned int)(n)))
#define R_Free(p) 	heap_free((caddr_t)p);
#define R_GET(p) 	get_pointer(p)
#define R_SET(p) 	get_offset(p)

static struct radix_node
	 *rn_insert(void *, struct radix_head *, int *, struct radix_node [2]),
	 *rn_newpair(void *, int, struct radix_node[2]),
	 *rn_search(void *, struct radix_node *),
	 *rn_search_m(void *, struct radix_node *, void *);
static struct radix_node *rn_addmask(void *, struct radix_mask_head *, int,int);

static void rn_detachhead_internal(void *);

#define	RADIX_MAX_KEY_LEN	32

static int rn_lexobetter(void *m_arg, void *n_arg);
static struct radix_mask *rn_new_radix_mask(struct radix_node *tt, struct radix_mask *next);
static int rn_satisfies_leaf(struct radix_head *head, char *trial, struct radix_node *leaf, int skip);

/*
 * The data structure for the keys is a radix tree with one way
 * branching removed.  The index rn_bit at an internal node n represents a bit
 * position to be tested.  The tree is arranged so that all descendants
 * of a node n have keys whose bits all agree up to position rn_bit - 1.
 * (We say the index of n is rn_bit.)
 *
 * There is at least one descendant which has a one bit at position rn_bit,
 * and at least one with a zero there.
 *
 * A route is determined by a pair of key and mask.  We require that the
 * bit-wise logical and of the key and mask to be the key.
 * We define the index of a route to associated with the mask to be
 * the first bit number in the mask where 0 occurs (with bit number 0
 * representing the highest order bit).
 *
 * We say a mask is normal if every bit is 0, past the index of the mask.
 * If a node n has a descendant (k, m) with index(m) == index(n) == rn_bit,
 * and m is a normal mask, then the route applies to every descendant of n.
 * If the index(m) < rn_bit, this implies the trailing last few bits of k
 * before bit b are all 0, (and hence consequently true of every descendant
 * of n), so the route applies to all descendants of the node as well.
 *
 * Similar logic shows that a non-normal mask m such that
 * index(m) <= index(n) could potentially apply to many children of n.
 * Thus, for each non-host route, we attach its mask to a list at an internal
 * node as high in the tree as we can go.
 *
 * The present version of the code makes use of normal routes in short-
 * circuiting an explict mask and compare operation when testing whether
 * a key satisfies a normal route, and also in remembering the unique leaf
 * that governs a subtree.
 */

/*
 * Most of the functions in this code assume that the key/mask arguments
 * are sockaddr-like structures, where the first byte is an unsigned char
 * indicating the size of the entire structure.
 *
 * To make the assumption more explicit, we use the LEN() macro to access
 * this field. It is safe to pass an expression with side effects
 * to LEN() as the argument is evaluated only once.
 * We cast the result to int as this is the dominant usage.
 */
//#define LEN(x) ( (int) (*(const unsigned char *)(x)) )
#define LEN(x) ( (int) (sizeof(struct sockaddr_in)))


/*
 * XXX THIS NEEDS TO BE FIXED
 * In the code, pointers to keys and masks are passed as either
 * 'void *' (because callers use to pass pointers of various kinds), or
 * 'caddr_t' (which is fine for pointer arithmetics, but not very
 * clean when you dereference it to access data). Furthermore, caddr_t
 * is really 'char *', while the natural type to operate on keys and
 * masks would be 'unsigned char'. This mismatch require a lot of casts and
 * intermediate variables to adapt types that clutter the code.
 */

/*
 * Search a node in the tree matching the key.
 */
static struct radix_node *
rn_search(void *v_arg, struct radix_node *head)
{
	struct radix_node *x;
	char *v = v_arg;

	//sal_print_info("search: start x %p\n", head);
	for (x = head, v = v_arg; x->rn_bit >= 0;) {
		if (x->rn_bmask & v[x->rn_offset]) {
			//sal_print_info("search: right %p\n", R_GET(x->rn_right));
			x = R_GET(x->rn_right);
		} else {
			//sal_print_info("search: left %p\n", R_GET(x->rn_left));
			x = R_GET(x->rn_left);
		}
	}
	//sal_print_info("search: done x %p\n", x);
	return (x);
}

/*
 * Same as above, but with an additional mask.
 * XXX note this function is used only once.
 */
static struct radix_node *
rn_search_m(void *v_arg, struct radix_node *head, void *m_arg)
{
	struct radix_node *x;
	char *v = v_arg, *m = m_arg;

	for (x = head; x->rn_bit >= 0;) {
		if ((x->rn_bmask & m[x->rn_offset]) &&
		    (x->rn_bmask & v[x->rn_offset]))
			x = R_GET(x->rn_right);
		else
			x = R_GET(x->rn_left);
	}
	return (x);
}

int
bin_rn_refines(void *m_arg, void *n_arg)
{
	char *m = m_arg, *n = n_arg;
	char *lim, *lim2 = lim = n + LEN(n);
	int longer = LEN(n++) - LEN(m++);
	int masks_are_equal = 1;

	if (longer > 0)
		lim -= longer;
	while (n < lim) {
		if (*n & ~(*m))
			return (0);
		if (*n++ != *m++)
			masks_are_equal = 0;
	}
	while (n < lim2)
		if (*n++)
			return (0);
	if (masks_are_equal && (longer < 0))
		for (lim2 = m - longer; m < lim2; )
			if (*m++)
				return (1);
	return (!masks_are_equal);
}

/*
 * Search for exact match in given @head.
 * Assume host bits are cleared in @v_arg if @m_arg is not NULL
 * Note that prefixes with /32 or /128 masks are treated differently
 * from host routes.
 */
struct radix_node *
bin_rn_lookup(void *v_arg, void *m_arg, struct radix_tree *tree)
{
	struct radix_node_head *nh = R_GET(tree->head);
	struct radix_head *head = &nh->rh;
	struct radix_node *x, *t;
	char *netmask;

	if (m_arg != NULL) {
		/*
		 * Most common case: search exact prefix/mask
		 */
		t = R_GET(head->rnh_treetop);
		x = rn_addmask(m_arg, R_GET(head->rnh_masks), 1, t->rn_offset);
		if (x == NULL)
			return (NULL);
		netmask = R_GET(x->rn_key);

		x = bin_rn_match(v_arg, tree);

		while (x != NULL && R_GET(x->rn_mask) != netmask)
			x = R_GET(x->rn_dupedkey);

		return (x);
	}

	/*
	 * Search for host address.
	 */
	if ((x = bin_rn_match(v_arg, tree)) == NULL)
		return (NULL);

	/* Check if found key is the same */
	if (LEN(R_GET(x->rn_key)) != LEN(v_arg) || memcmp(R_GET(x->rn_key), v_arg, LEN(v_arg)))
		return (NULL);

	/* Check if this is not host route */
	if (x->rn_mask)
		return (NULL);

	return (x);
}

static int
rn_satisfies_leaf(struct radix_head *head, char *trial, struct radix_node *leaf, int skip)
{
	char *cp = trial, *cp2 = R_GET(leaf->rn_key), *cp3 = R_GET(leaf->rn_mask);
	char *cplim;
	int length = MIN(LEN(cp), LEN(cp2));

	if (cp3 == NULL)
		cp3 = R_GET(head->rn_ones);
	else
		length = MIN(length, LEN(cp3));

	cplim = cp + length; cp3 += skip; cp2 += skip;
	for (cp += skip; cp < cplim; cp++, cp2++, cp3++)
		if ((*cp ^ *cp2) & *cp3)
			return (0);
	return (1);
}

/*
 * Search for longest-prefix match in given @head
 */
struct radix_node *
bin_rn_match(void *v_arg, struct radix_tree *tree)
{
	struct radix_node_head *nh = R_GET(tree->head);
	struct radix_head *head = &nh->rh;
	char *v = v_arg;
	struct radix_node *t = R_GET(head->rnh_treetop), *x;
	char *cp = v, *cp2;
	char *cplim, *m;
	struct radix_node *saved_t, *top = t;
	int off = t->rn_offset, vlen = LEN(cp), matched_off;
	int test, b, rn_bit;

	/*
	 * Open code rn_search(v, top) to avoid overhead of extra
	 * subroutine call.
	 */
	for (; t->rn_bit >= 0; ) {
		if (t->rn_bmask & cp[t->rn_offset])
			t = R_GET(t->rn_right);
		else
			t = R_GET(t->rn_left);
	}
	/*
	 * See if we match exactly as a host destination
	 * or at least learn how many bits match, for normal mask finesse.
	 *
	 * It doesn't hurt us to limit how many bytes to check
	 * to the length of the mask, since if it matches we had a genuine
	 * match and the leaf we have is the most specific one anyway;
	 * if it didn't match with a shorter length it would fail
	 * with a long one.  This wins big for class B&C netmasks which
	 * are probably the most common case...
	 */
	if (t->rn_mask) {
		m = R_GET(t->rn_mask);
		vlen = *m;
	}
	cp += off; cp2 = R_GET(t->rn_key) + off; cplim = v + vlen;
	for (; cp < cplim; cp++, cp2++)
		if (*cp != *cp2)
			goto on1;
	/*
	 * This extra grot is in case we are explicitly asked
	 * to look up the default.  Ugh!
	 *
	 * Never return the root node itself, it seems to cause a
	 * lot of confusion.
	 */
	if (t->rn_flags & RNF_ROOT)
		t = R_GET(t->rn_dupedkey);
	return (t);
on1:
	test = (*cp ^ *cp2) & 0xff; /* find first bit that differs */
	for (b = 7; (test >>= 1) > 0;)
		b--;
	matched_off = cp - v;
	b += matched_off << 3;
	rn_bit = -1 - b;
	/*
	 * If there is a host route in a duped-key chain, it will be first.
	 */
	saved_t = t;
	if (!t->rn_mask)
		t = R_GET(t->rn_dupedkey);
	for (; t; t = R_GET(t->rn_dupedkey))
		/*
		 * Even if we don't match exactly as a host,
		 * we may match if the leaf we wound up at is
		 * a route to a net.
		 */
		if (t->rn_flags & RNF_NORMAL) {
			if (rn_bit <= t->rn_bit)
				return (t);
		} else if (rn_satisfies_leaf(head, v, t, matched_off))
			return (t);
	t = saved_t;
	/* start searching up the tree */
	do {
		struct radix_mask *m;
		t = R_GET(t->rn_parent);
		m = R_GET(t->rn_mklist);
		/*
		 * If non-contiguous masks ever become important
		 * we can restore the masking and open coding of
		 * the search and satisfaction test and put the
		 * calculation of "off" back before the "do".
		 */
		while (m) {
			if (m->rm_flags & RNF_NORMAL) {
				if (rn_bit <= m->rm_bit)
					return (R_GET(m->rm_leaf));
			} else {
				off = MIN(t->rn_offset, matched_off);
				x = rn_search_m(v, t, R_GET(m->rm_mask));
				while (x && x->rn_mask != m->rm_mask)
					x = R_GET(x->rn_dupedkey);
				if (x && rn_satisfies_leaf(head, v, x, off))
					return (x);
			}
			m = R_GET(m->rm_mklist);
		}
	} while (t != top);
	return (0);
}

#ifdef RN_DEBUG
int	rn_nodenum;
struct	radix_node *rn_clist;
int	rn_saveinfo;
int	rn_debug =  1;
#endif

/*
 * Whenever we add a new leaf to the tree, we also add a parent node,
 * so we allocate them as an array of two elements: the first one must be
 * the leaf (see RNTORT() in route.c), the second one is the parent.
 * This routine initializes the relevant fields of the nodes, so that
 * the leaf is the left child of the parent node, and both nodes have
 * (almost) all all fields filled as appropriate.
 * (XXX some fields are left unset, see the '#if 0' section).
 * The function returns a pointer to the parent node.
 */

static struct radix_node *
rn_newpair(void *v, int b, struct radix_node nodes[2])
{
	struct radix_node *tt = nodes, *t = tt + 1;
	t->rn_bit = b;
	t->rn_bmask = 0x80 >> (b & 7);
	t->rn_left = R_SET(tt);
	t->rn_offset = b >> 3;

#if 0  /* XXX perhaps we should fill these fields as well. */
	t->rn_parent = t->rn_right = NULL;

	tt->rn_mask = NULL;
	tt->rn_dupedkey = NULL;
	tt->rn_bmask = 0;
#endif
	tt->rn_bit = -1;
	tt->rn_key = R_SET(v);
	tt->rn_parent = R_SET(t);
	tt->rn_flags = t->rn_flags = RNF_ACTIVE;
	tt->rn_mklist = t->rn_mklist = 0;
#ifdef RN_DEBUG
	tt->rn_info = rn_nodenum++; t->rn_info = rn_nodenum++;
	tt->rn_twin = t;
	tt->rn_ybro = rn_clist;
	rn_clist = tt;
#endif
	return (t);
}

static struct radix_node *
rn_insert(void *v_arg, struct radix_head *head, int *dupentry,
    struct radix_node nodes[2])
{
	char *v = v_arg;
	struct radix_node *top = R_GET(head->rnh_treetop);
	int head_off = top->rn_offset, vlen = LEN(v);
	struct radix_node *t = rn_search(v_arg, top);
	char *cp = v + head_off;
	int b;
	struct radix_node *p, *tt, *x;
	char *cp2;
	int cmp_res;
	char *cplim;
   	/*
	 * Find first bit at which v and t->rn_key differ
	 */
	cp2 = R_GET(t->rn_key) + head_off;
	cplim = v + vlen;

	while (cp < cplim)
		if (*cp2++ != *cp++)
			goto on1;
	*dupentry = 1;
	return (t);
on1:
	*dupentry = 0;
	cmp_res = (cp[-1] ^ cp2[-1]) & 0xff;
	for (b = (cp - v) << 3; cmp_res; b--)
		cmp_res >>= 1;

	x = top;
	cp = v;
	do {
		p = x;
		if (cp[x->rn_offset] & x->rn_bmask)
			x = R_GET(x->rn_right);
		else
			x = R_GET(x->rn_left);
	} while (b > (unsigned) x->rn_bit);
	/* x->rn_bit < b && x->rn_bit >= 0 */
#ifdef RN_DEBUG
	if (rn_debug)
		sal_print_info( "rn_insert: Going In:\n"), traverse(p);
#endif
	t = rn_newpair(v_arg, b, nodes);
	tt = R_GET(t->rn_left);
	if ((cp[p->rn_offset] & p->rn_bmask) == 0) {
		p->rn_left = R_SET(t);
	} else {
		p->rn_right = R_SET(t);
	}
	x->rn_parent = R_SET(t);
	t->rn_parent = R_SET(p); /* frees x, p as temp vars below */
	if ((cp[t->rn_offset] & t->rn_bmask) == 0) {
		t->rn_right = R_SET(x);
	} else {
		t->rn_right = R_SET(tt);
		t->rn_left = R_SET(x);
	}
#ifdef RN_DEBUG
	if (rn_debug)
		sal_print_info( "rn_insert: Coming Out:\n"), traverse(p);
#endif
	return (tt);
}

static struct radix_node *
rn_addmask(void *n_arg, struct radix_mask_head *maskhead, int search, int skip)
{
	unsigned char *netmask = n_arg;
	unsigned char *cp, *cplim;
	unsigned char *d;
	struct radix_node *x;
	int b = 0, mlen, j/*, i*/;
	int maskduplicated, isnormal;
	struct radix_node *saved_x;
	unsigned char addmask_key[RADIX_MAX_KEY_LEN];

	if ((mlen = LEN(netmask)) > RADIX_MAX_KEY_LEN)
		mlen = RADIX_MAX_KEY_LEN;
	if (skip == 0)
		skip = 1;
	if (mlen <= skip) {
		return (maskhead->mask_nodes);
	}

	memset(addmask_key, 0, RADIX_MAX_KEY_LEN);
	if (skip > 1) {
		d = R_GET(maskhead->head.rn_ones);
		memcpy(addmask_key + 1, d + 1, skip - 1);
	}
	memcpy(addmask_key + skip, netmask + skip, mlen - skip);
	/*
	 * Trim trailing zeroes.
	 */
	for (cp = addmask_key + mlen; (cp > addmask_key) && cp[-1] == 0;) {
		cp--;
	}
	mlen = cp - addmask_key;
	if (mlen <= skip) {
		return (maskhead->mask_nodes);
	}
	*addmask_key = mlen;
	x = rn_search(addmask_key, R_GET(maskhead->head.rnh_treetop));
	if (memcmp(addmask_key, R_GET(x->rn_key), mlen) != 0) {
		x = NULL;
	}
	if (x || search) {
		return (x);
	}
	R_Zalloc(x, struct radix_node *, RADIX_MAX_KEY_LEN + 2 * sizeof (*x));
	if ((saved_x = x) == NULL) {
		return (NULL);
	}
	netmask = cp = (unsigned char *)(x + 2);
	memcpy(cp, addmask_key, mlen);
	x = rn_insert(cp, &maskhead->head, &maskduplicated, x);
	if (maskduplicated) {
		R_Free(saved_x);
		return (x);
	}
	/*
	 * Calculate index of mask, and check for normalcy.
	 * First find the first byte with a 0 bit, then if there are
	 * more bits left (remember we already trimmed the trailing 0's),
	 * the bits should be contiguous, otherwise we have got
	 * a non-contiguous mask.
	 */
#define	CONTIG(_c)	(((~(_c) + 1) & (_c)) == (unsigned char)(~(_c) + 1))
	cplim = netmask + mlen;
	isnormal = 1;
	for (cp = netmask + skip; (cp < cplim) && *(unsigned char *)cp == 0xff;)
		cp++;
	if (cp != cplim) {
		for (j = 0x80; (j & *cp) != 0; j >>= 1)
			b++;
		if (!CONTIG(*cp) || cp != (cplim - 1))
			isnormal = 0;
	}
	b += (cp - netmask) << 3;
	x->rn_bit = -1 - b;
	if (isnormal)
		x->rn_flags |= RNF_NORMAL;
	return (x);
}

static int	/* XXX: arbitrary ordering for non-contiguous masks */
rn_lexobetter(void *m_arg, void *n_arg)
{
	unsigned char *mp = m_arg, *np = n_arg, *lim;

	if (LEN(mp) > LEN(np))
		return (1);  /* not really, but need to check longer one first */
	if (LEN(mp) == LEN(np))
		for (lim = mp + LEN(mp); mp < lim;)
			if (*mp++ > *np++)
				return (1);
	return (0);
}

static struct radix_mask *
rn_new_radix_mask(struct radix_node *tt, struct radix_mask *next)
{
	struct radix_mask *m;

	R_Malloc(m, struct radix_mask *, sizeof (struct radix_mask));
	if (m == NULL) {
		radix_err("Failed to allocate route mask\n");
		return (0);
	}
	memset(m, 0, sizeof(*m));
	m->rm_bit = tt->rn_bit;
	m->rm_flags = tt->rn_flags;
	if (tt->rn_flags & RNF_NORMAL)
		m->rm_leaf = R_SET(tt);
	else
		m->rm_mask = tt->rn_mask;
	m->rm_mklist = R_SET(next);
	tt->rn_mklist = R_SET(m);
	return (m);
}

struct radix_node *
bin_rn_addroute(void *v_arg, void *n_arg, struct radix_tree *tree,
    struct radix_node treenodes[2])
{
	char *v = (char *)v_arg, *netmask = (char *)n_arg;
	struct radix_node_head *nh = R_GET(tree->head);
	struct radix_head *head = &nh->rh;
	struct radix_node *t, *x = NULL, *tt, *d, *dd;
	struct radix_node *saved_tt, *top = R_GET(head->rnh_treetop);
	short b = 0, b_leaf = 0;
	int keyduplicated;
	char *mmask;
	struct radix_mask *m, **mp, *mt, *mtt;
	//int count;

	/*
	 * In dealing with non-contiguous masks, there may be
	 * many different routes which have the same mask.
	 * We will find it useful to have a unique pointer to
	 * the mask to speed avoiding duplicate references at
	 * nodes and possibly save time in calculating indices.
	 */
	if (netmask)  {
		x = rn_addmask(netmask, R_GET(head->rnh_masks), 0, top->rn_offset);
		if (x == NULL) {
			return (0);
		}
		b_leaf = x->rn_bit;
		b = -1 - x->rn_bit;
		netmask = R_GET(x->rn_key);
	}
	/*
	 * Deal with duplicated keys: attach node to previous instance
	 */
	saved_tt = tt = rn_insert(v, head, &keyduplicated, treenodes);
	if (keyduplicated) {
		for (t = tt; tt; t = tt, tt = R_GET(tt->rn_dupedkey)) {
#ifdef RADIX_MPATH
			/* permit multipath, if enabled for the family */
			if (rn_mpath_capable(head) && netmask == R_GET(tt->rn_mask)) {
				/*
				 * go down to the end of multipaths, so that
				 * new entry goes into the end of rn_dupedkey
				 * chain.
				 */
				do {
					t = tt;
					tt = R_GET(tt->rn_dupedkey);
				} while (tt && t->rn_mask == tt->rn_mask);
				break;
			}
#endif // RADIX_MPATH
			if (R_GET(tt->rn_mask) == netmask) {
				ba_or(&tt[1].private.rules, &tt[1].private.rules, &treenodes[1].private.rules);
				return (0);
			}
			if (netmask == NULL ||
			    (tt->rn_mask &&
			     ((b_leaf < tt->rn_bit) /* index(netmask) > node */
			      || bin_rn_refines(netmask, R_GET(tt->rn_mask))
			      || rn_lexobetter(netmask, R_GET(tt->rn_mask)))))
				break;
		}
		/*
		 * If the mask is not duplicated, we wouldn't
		 * find it among possible duplicate key entries
		 * anyway, so the above test doesn't hurt.
		 *
		 * We sort the masks for a duplicated key the same way as
		 * in a masklist -- most specific to least specific.
		 * This may require the unfortunate nuisance of relocating
		 * the head of the list.
		 *
		 * We also reverse, or doubly link the list through the
		 * parent pointer.
		 */
		if (tt == saved_tt) {
			struct	radix_node *xx = x;
			/* link in at head of list */
			(tt = treenodes)->rn_dupedkey = R_SET(t);
			tt->rn_flags = t->rn_flags;
			tt->rn_parent = t->rn_parent;
			x = R_GET(t->rn_parent);
			t->rn_parent = R_SET(tt);	 		/* parent */
			if (R_GET(x->rn_left) == t) {
				x->rn_left = R_SET(tt);
			} else {
				x->rn_right = R_SET(tt);
			}
			saved_tt = tt; x = xx;
		} else {
			(tt = treenodes)->rn_dupedkey = t->rn_dupedkey;
			t->rn_dupedkey = R_SET(tt);
			tt->rn_parent = R_SET(t);			/* parent */
			if (tt->rn_dupedkey) {
				d = R_GET(tt->rn_dupedkey);
				d->rn_parent = R_SET(tt); /* parent */
			}
		}
#ifdef RN_DEBUG
		t=tt+1; tt->rn_info = rn_nodenum++; t->rn_info = rn_nodenum++;
		tt->rn_twin = t; tt->rn_ybro = rn_clist; rn_clist = tt;
#endif
		tt->rn_key = R_SET(v);
		tt->rn_bit = -1;
		tt->rn_flags = RNF_ACTIVE;
	}
	/*
	 * Put mask in tree.
	 */
	if (netmask) {
		tt->rn_mask = R_SET(netmask);
		tt->rn_bit = x->rn_bit;
		tt->rn_flags |= x->rn_flags & RNF_NORMAL;
	}
	t = R_GET(saved_tt->rn_parent);
	if (keyduplicated)
		goto on2;
	b_leaf = -1 - t->rn_bit;
	if (R_GET(t->rn_right) == saved_tt)
		x = R_GET(t->rn_left);
	else
		x = R_GET(t->rn_right);
	/* Promote general routes from below */
	if (x->rn_bit < 0) {
		mtt = NULL;
		dd = t;
		m = R_GET(t->rn_mklist);
	    for (mp = &m; x; x = R_GET(x->rn_dupedkey)) {
	    	if (x->rn_mask && (x->rn_bit >= b_leaf) && x->rn_mklist == 0) {
	    		*mp = m = rn_new_radix_mask(x, 0);
	    		if (mtt) {
	    			mtt->rm_mklist = R_SET(m);
	    		} else {
	    			dd->rn_mklist = R_SET(m);
	    		}
	    		if (m) {
	    			mtt = m;
	    			mt = R_GET(m->rm_mklist);
	    			mp = &mt;
	    		}
	    	}
	    }
	} else if (x->rn_mklist) {
		/*
		 * Skip over masks whose index is > that of new node
		 */
		mtt = NULL;
		dd = x;
		mt = R_GET(x->rn_mklist);
		for (mp = &mt; (m = *mp); mp = &mt) {
			if (m->rm_bit >= b_leaf)
				break;
			mtt = m;
			mt = R_GET(m->rm_mklist);
		}
		t->rn_mklist = R_SET(m);
		if (mtt) {
			mtt->rm_mklist = 0;
		} else {
			dd->rn_mklist = 0;
		}
		*mp = NULL;
	}
on2:
	/* Add new route to highest possible ancestor's list */
	if ((netmask == 0) || (b > t->rn_bit )) {
		return (tt); /* can't lift at all */
	}
	b_leaf = tt->rn_bit;
	do {
		x = t;
		t = R_GET(t->rn_parent);
	} while (b <= t->rn_bit && x != top);
	/*
	 * Search through routes associated with node to
	 * insert new route according to index.
	 * Need same criteria as when sorting dupedkeys to avoid
	 * double loop on deletion.
	 */
	mtt = NULL;
	dd = x;
	mt = R_GET(x->rn_mklist);
	for (mp = &mt; (m = *mp); mp = &mt) {
		if (m->rm_bit < b_leaf) {
			mtt = m;
			mt = R_GET(m->rm_mklist);
			continue;
		}
		if (m->rm_bit > b_leaf)
			break;
		if (m->rm_flags & RNF_NORMAL) {
			d = R_GET(m->rm_leaf);
			mmask = R_GET(d->rn_mask);
			if (tt->rn_flags & RNF_NORMAL) {
#if !defined(RADIX_MPATH)
				radix_err("Non-unique normal route, mask not entered\n");
#endif
				return (tt);
			}
		} else
			mmask = R_GET(m->rm_mask);
		if (mmask == netmask) {
			m->rm_refs++;
			tt->rn_mklist = R_SET(m);
			return (tt);
		}
		if (bin_rn_refines(netmask, mmask)
		    || rn_lexobetter(netmask, mmask))
			break;
		mtt = m;
		mt = R_GET(m->rm_mklist);
	}
	*mp = rn_new_radix_mask(tt, *mp);
	if (mtt) {
		mtt->rm_mklist = R_SET(*mp);
	} else {
		dd->rn_mklist = R_SET(*mp);
	}
	return (tt);
}

static struct radix_node *
rn_delete_head(void *v_arg, void *netmask_arg, struct radix_head *head)
{
	struct radix_node *t, *p, *x, *tt, *d, *dd;
	struct radix_mask *m, *saved_m, **mp, *mt, *mtt;
	struct radix_node *dupedkey, *saved_tt, *top;
	char *v, *netmask;
	int b, head_off, vlen;

	v = v_arg;
	netmask = netmask_arg;
	x = R_GET(head->rnh_treetop);
	tt = rn_search(v, x);
	head_off = x->rn_offset;
	vlen =  LEN(v);
	saved_tt = tt;
	top = x;
	if (tt == NULL ||
	    memcmp(v + head_off, R_GET(tt->rn_key) + head_off, vlen - head_off))
		return (0);
	/*
	 * Delete our route from mask lists.
	 */
	if (netmask) {
		x = rn_addmask(netmask, R_GET(head->rnh_masks), 1, head_off);
		if (x == NULL) {
			return (0);
		}
		netmask = R_GET(x->rn_key);
		while (R_GET(tt->rn_mask) != netmask)
			if ((tt = R_GET(tt->rn_dupedkey)) == NULL) {
				return (0);
			}
	}
	if (tt->rn_mask == 0 || (saved_m = m = R_GET(tt->rn_mklist)) == NULL) {
		goto on1;
	}
	if (tt->rn_flags & RNF_NORMAL) {
		if (R_GET(m->rm_leaf) != tt || m->rm_refs > 0) {
			radix_err("bin_rn_delete: inconsistent annotation\n");
			return (0);  /* dangling ref could cause disaster */
		}
	} else {
		if (m->rm_mask != tt->rn_mask) {
			radix_err("bin_rn_delete: inconsistent annotation\n");
			goto on1;
		}
		if (--m->rm_refs >= 0)
			goto on1;
	}
	b = -1 - tt->rn_bit;
	t = R_GET(saved_tt->rn_parent);
	if (b > t->rn_bit)
		goto on1; /* Wasn't lifted at all */
	do {
		x = t;
		t = R_GET(t->rn_parent);
	} while (b <= t->rn_bit && x != top);
	mtt = NULL;
	dd = x;
	mt = R_GET(x->rn_mklist);
	mp = &mt;
	for (mp = &mt; (m = *mp); mp = &mt) {
		if (m == saved_m) {
			if (mtt)
				mtt->rm_mklist = m->rm_mklist;
			else
				dd->rn_mklist = m->rm_mklist;
			*mp = R_GET(m->rm_mklist);
			R_Free(m);
			break;
		}
		mtt = m;
		mt = R_GET(m->rm_mklist);
	}
	if (m == NULL) {
		radix_err("bin_rn_delete: couldn't find our annotation\n");
		if (tt->rn_flags & RNF_NORMAL)
			return (0); /* Dangling ref to us */
	}
on1:
	/*
	 * Eliminate us from tree
	 */
	if (tt->rn_flags & RNF_ROOT) {
		return (0);
	}
#ifdef RN_DEBUG
	/* Get us out of the creation list */
	for (t = rn_clist; t && t->rn_ybro != tt; t = t->rn_ybro) {}
	if (t) t->rn_ybro = tt->rn_ybro;
#endif
	t = R_GET(tt->rn_parent);
	dupedkey = R_GET(saved_tt->rn_dupedkey);
	if (dupedkey) {
		/*
		 * Here, tt is the deletion target and
		 * saved_tt is the head of the dupekey chain.
		 */
		if (tt == saved_tt) {
			/* remove from head of chain */
			x = dupedkey;
			x->rn_parent = R_SET(t);
			if (R_GET(t->rn_left) == tt)
				t->rn_left = R_SET(x);
			else
				t->rn_right = R_SET(x);
		} else {
			/* find node in front of tt on the chain */
			for (x = p = saved_tt; p && R_GET(p->rn_dupedkey) != tt;)
				p = R_GET(p->rn_dupedkey);
			if (p) {
				p->rn_dupedkey = tt->rn_dupedkey;
				if (tt->rn_dupedkey) { /* parent */
					d = R_GET(tt->rn_dupedkey);
					d->rn_parent = R_SET(p);
				}
			} else
				radix_err("bin_rn_delete: couldn't find us");
		}
		t = tt + 1;
		if  (t->rn_flags & RNF_ACTIVE) {
#ifndef RN_DEBUG
			*++x = *t;
			p = R_GET(t->rn_parent);
#else
			b = t->rn_info;
			*++x = *t;
			t->rn_info = b;
			p = t->rn_parent;
#endif
			if (R_GET(p->rn_left) == t)
				p->rn_left = R_SET(x);
			else
				p->rn_right = R_SET(x);
			d = R_GET(x->rn_left);
			d->rn_parent = R_SET(x);
			d = R_GET(x->rn_right);
			d->rn_parent = R_SET(x);
		}
		goto out;
	}
	if (R_GET(t->rn_left) == tt)
		x = R_GET(t->rn_right);
	else
		x = R_GET(t->rn_left);
	p = R_GET(t->rn_parent);
	if (R_GET(p->rn_right) == t)
		p->rn_right = R_SET(x);
	else
		p->rn_left = R_SET(x);
	x->rn_parent = R_SET(p);
	/*
	 * Demote routes attached to us.
	 */
	if (t->rn_mklist) {
		if (x->rn_bit >= 0) {
			mtt = NULL;
			dd = x;
			mt = R_GET(x->rn_mklist);
			for (mp = &mt; (m = *mp);) {
				mtt = m;
				mt = R_GET(m->rm_mklist);
				mp = &mt;
			}
			if (mtt)
				mtt->rm_mklist = t->rn_mklist;
			else
				dd->rn_mklist = t->rn_mklist;
			*mp = R_GET(t->rn_mklist);
		} else {
			/* If there are any key,mask pairs in a sibling
			   duped-key chain, some subset will appear sorted
			   in the same order attached to our mklist */
			for (m = R_GET(t->rn_mklist); m && x; x = R_GET(x->rn_dupedkey))
				if (m == R_GET(x->rn_mklist)) {
					struct radix_mask *mm = R_GET(m->rm_mklist);
					x->rn_mklist = 0;
					if (--(m->rm_refs) < 0) {
						R_Free(m);
					}
					m = mm;
				}
			if (m)
				radix_err("bin_rn_delete: Orphaned Mask %p at %p", m, x);
		}
	}
	/*
	 * We may be holding an active internal node in the tree.
	 */
	x = tt + 1;
	if (t != x) {
#ifndef RN_DEBUG
		*t = *x;
#else
		b = t->rn_info;
		*t = *x;
		t->rn_info = b;
#endif
		d = R_GET(t->rn_left);
		d->rn_parent = R_SET(t);
		d = R_GET(t->rn_right);
		d->rn_parent = R_SET(t);
		p = R_GET(x->rn_parent);
		if (R_GET(p->rn_left) == x)
			p->rn_left = R_SET(t);
		else
			p->rn_right = R_SET(t);
	}
out:
	tt->rn_flags &= ~RNF_ACTIVE;
	tt[1].rn_flags &= ~RNF_ACTIVE;
	return (tt);
}

struct radix_node *
bin_rn_delete(void *v_arg, void *netmask_arg, struct radix_tree *tree)
{
	struct radix_node_head *nh = R_GET(tree->head);
	struct radix_head *h = &nh->rh;
	return rn_delete_head(v_arg, netmask_arg, h);
}

/*
 * This is the same as bin_rn_walktree() except for the parameters and the
 * exit.
 */
int
bin_rn_walktree_from(struct radix_tree *t, void *a, void *m, walktree_f_t *f, void *w)
{
	int error;
	struct radix_node_head *nh = R_GET(t->head);
	struct radix_head *h = &nh->rh;
	struct radix_node *base, *next;
	unsigned char *xa = (unsigned char *)a;
	unsigned char *xm = (unsigned char *)m;
	struct radix_node *rn, *d, *last = NULL; /* shut up gcc */
	int stopping = 0;
	int lastb;
#ifdef RN_DEBUG
	struct sockaddr_in *da = (struct sockaddr_in *)a;
	struct sockaddr_in *dm = (struct sockaddr_in *)m;
#endif // RN_DEBUG

	if(m == NULL)
		radix_err("%s: mask needs to be specified", __func__);

#ifdef RN_DEBUG
	sal_print_info("bin_rn_walktree_from: a = %d.%d.%d.%d, mask = %d.%d.%d.%d\n",
			da->sin_addr.s_addr & 0xff,
			(da->sin_addr.s_addr & 0xff00)>> 8,
			(da->sin_addr.s_addr & 0x00ff0000)>>16,
			(da->sin_addr.s_addr & 0xff000000)>>24,
			dm->sin_addr.s_addr & 0xff,
			(dm->sin_addr.s_addr & 0xff00)>> 8,
			(dm->sin_addr.s_addr & 0x00ff0000)>>16,
			(dm->sin_addr.s_addr & 0xff000000)>>24);
#endif // RN_DEBUG

	/*
	 * rn_search_m is sort-of-open-coded here. We cannot use the
	 * function because we need to keep track of the last node seen.
	 */
	for (rn = R_GET(h->rnh_treetop); rn->rn_bit >= 0; ) {
		last = rn;
		if (!(rn->rn_bmask & xm[rn->rn_offset])) {
			break;
		}
		if (rn->rn_bmask & xa[rn->rn_offset]) {
			rn = R_GET(rn->rn_right);
		} else {
			rn = R_GET(rn->rn_left);
		}
	}

	/*
	 * Two cases: either we stepped off the end of our mask,
	 * in which case last == rn, or we reached a leaf, in which
	 * case we want to start from the leaf.
	 */
	if (rn->rn_bit >= 0)
		rn = last;
	lastb = last->rn_bit;

	/*
	 * This gets complicated because we may delete the node
	 * while applying the function f to it, so we need to calculate
	 * the successor node in advance.
	 */
	while (rn->rn_bit >= 0) {
		rn = R_GET(rn->rn_left);
	}

	while (!stopping) {
		base = rn;
		/* If at right child go back up, otherwise, go right */
		while ((d = R_GET(rn->rn_parent)) && R_GET(d->rn_right) == rn
		       && !(rn->rn_flags & RNF_ROOT)) {
			rn = d;

			/* if went up beyond last, stop */
			if (rn->rn_bit <= lastb) {
				stopping = 1;
				/*
				 * XXX we should jump to the 'Process leaves'
				 * part, because the values of 'rn' and 'next'
				 * we compute will not be used. Not a big deal
				 * because this loop will terminate, but it is
				 * inefficient and hard to understand!
				 */
			}
		}
		
		/* 
		 * At the top of the tree, no need to traverse the right
		 * half, prevent the traversal of the entire tree in the
		 * case of default route.
		 */
		if (d->rn_flags & RNF_ROOT)
			stopping = 1;

		/* Find the next *leaf* since next node might vanish, too */
		for (rn = R_GET(d->rn_right); rn->rn_bit >= 0;) {
			rn = R_GET(rn->rn_left);
		}
		next = rn;
		/* Process leaves */
		while ((rn = base) != NULL) {
			base = R_GET(rn->rn_dupedkey);
			if (!(rn->rn_flags & RNF_ROOT)
			    && (error = (*f)(rn, w)))
				return (error);
		}
		rn = next;

		if (rn->rn_flags & RNF_ROOT) {
			stopping = 1;
		}
	}
	return (0);
}

static int
rn_walktree_head(struct radix_head *h, walktree_f_t *f, void *w)
{
	int error;
	struct radix_node *base, *next, *d;
	struct radix_node *rn = R_GET(h->rnh_treetop);

	/*
	 * This gets complicated because we may delete the node
	 * while applying the function f to it, so we need to calculate
	 * the successor node in advance.
	 */

	/* First time through node, go left */
	while (rn->rn_bit >= 0)
		rn = R_GET(rn->rn_left);
	for (;;) {
		base = rn;
		/* If at right child go back up, otherwise, go right */
		while ((d = R_GET(rn->rn_parent)) && R_GET(d->rn_right) == rn
		       && (rn->rn_flags & RNF_ROOT) == 0)
			rn = R_GET(rn->rn_parent);
		/* Find the next *leaf* since next node might vanish, too */
		d = R_GET(rn->rn_parent);
		for (rn = R_GET(d->rn_right); rn->rn_bit >= 0; d = R_GET(rn->rn_parent))
			rn = R_GET(rn->rn_left);
		next = rn;
		/* Process leaves */
		while ((rn = base)) {
			base = R_GET(rn->rn_dupedkey);
			if (!(rn->rn_flags & RNF_ROOT)
			    && (error = (*f)(rn, w)))
				return (error);
		}
		rn = next;
		if (rn->rn_flags & RNF_ROOT)
			return (0);
	}
	/* NOTREACHED */
	return (0);
}

int
bin_rn_walktree(struct radix_tree *t, walktree_f_t *f, void *w)
{
	struct radix_node_head *nh = R_GET(t->head);
	return rn_walktree_head(&nh->rh, f, w);
}

/*
 * Initialize an empty tree. This has 3 nodes, which are passed
 * via base_nodes (in the order <left,root,right>) and are
 * marked RNF_ROOT so they cannot be freed.
 * The leaves have all-zero and all-one keys, with significant
 * bits starting at 'off'.
 */
void
bin_rn_inithead_internal(struct radix_head *rh, struct radix_node *base_nodes, int off)
{
	struct radix_node *t, *tt, *ttt;

	t = rn_newpair(R_GET(rh->rn_zeros), off, base_nodes);

	ttt = base_nodes + 2;
	t->rn_right = R_SET(ttt);
	t->rn_parent = R_SET(t);
	tt = R_GET(t->rn_left);	/* ... which in turn is base_nodes */
	tt->rn_flags = t->rn_flags = RNF_ROOT | RNF_ACTIVE;
	tt->rn_bit = -1 - off;
	*ttt = *tt;
	ttt->rn_key = rh->rn_ones;

	rh->rnh_treetop = R_SET(t);
}

static void
rn_detachhead_internal(void *head)
{
	if (head == NULL) {
	    radix_err("%s: head already freed", __func__);
	    return;
	}
	
	/* Free <left,root,right> nodes. */
	R_Free(head);
}

/* Functions used by 'struct radix_node_head' users */
int
bin_rn_inithead(struct radix_tree *tree, int off)
{
	struct radix_mask_head *rmh;
	struct radix_node_head *rnh;
	char *arr_z, *arr_o;

	if (!tree)
		return (0);
	if (tree->head)
		return (1); // already initialized

	R_Zalloc(rnh, struct radix_node_head *, sizeof (*rnh));
	if (!rnh)
		return (0);
	R_Zalloc(rmh, struct radix_mask_head *, sizeof (*rmh));
	if (!rmh) {
		R_Free(rnh);
		return (0);
	}
	R_Zalloc(arr_z, char *, RADIX_MAX_KEY_LEN * sizeof(char));
	if (!arr_z) {
		R_Free(rnh);
		R_Free(rmh);
		return (0);
	}
	R_Malloc(arr_o, char *, RADIX_MAX_KEY_LEN * sizeof(char));
	if (!arr_o) {
		R_Free(rnh);
		R_Free(rmh);
		R_Free(arr_z);
		return (0);
	}
	memset(arr_o, -1, RADIX_MAX_KEY_LEN * sizeof(char));
	rnh->rh.rn_zeros = R_SET(arr_z);
	rnh->rh.rn_ones = R_SET(arr_o);
	rmh->head.rn_zeros = R_SET(arr_z);
	rmh->head.rn_ones = R_SET(arr_o);

	/* Init trees */
	bin_rn_inithead_internal(&rnh->rh, rnh->rnh_nodes, off);
	bin_rn_inithead_internal(&rmh->head, rmh->mask_nodes, 0);
	rnh->rh.rnh_masks = R_SET(rmh);
	tree->head = R_SET(rnh);

	/* Finally, set base callbacks */
	rnh->rnh_addaddr = bin_rn_addroute;
	rnh->rnh_deladdr = bin_rn_delete;
	rnh->rnh_matchaddr = bin_rn_match;
	rnh->rnh_lookup = bin_rn_lookup;
	rnh->rnh_walktree = bin_rn_walktree;
	rnh->rnh_walktree_from = bin_rn_walktree_from;

	return (1);
}

static int
rn_freeentry(struct radix_node *rn, void *arg)
{
	struct radix_head * const h = arg;
	struct radix_node *x;

	x = (struct radix_node *)rn_delete_head(rn + 2, NULL, h);
	if (x != NULL) {
		R_Free(x);
	}
	return (0);
}

int
bin_rn_rn_detachhead(struct radix_tree *tree)
{
	struct radix_node_head *nh;
	struct radix_mask_head *mh;

	if (!tree->head) {
	    radix_err("%s: head already freed", __func__);
	    return(1);
	}

	nh = R_GET(tree->head);
	mh = R_GET(nh->rh.rnh_masks);
	rn_walktree_head(&mh->head, rn_freeentry, mh);
	rn_detachhead_internal(mh);
	rn_detachhead_internal(nh);
	tree->head = 0;
	return (1);
}
