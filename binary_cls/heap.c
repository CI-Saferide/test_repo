#include <stddef.h>
#include "aux.h"
#include "heap.h"
#include "classifier.h"

#ifdef HEAP_DEBUG
#define heap_dbg cls_dbg
#else
#define heap_dbg(...)
#endif

static heap_t heap = {
	.bins = NULL,
	.end = NULL,
	.heap_size = 0,
	.start = NULL,
};

typedef struct node_t {
	unsigned int hole;
	unsigned int size;
	unsigned int next;
	unsigned int prev;
} node_t;

typedef struct {
	unsigned int header;
	unsigned int pad; /* this pas will make sure all addresses are aligned to 8 */
} footer_t;

#define OVERHEAD (sizeof(footer_t) + sizeof(node_t))

unsigned int get_offset(void *node)
{
	if (node == NULL)
		return 0;

	return ((unsigned char*)node - (unsigned char*)heap.start) + 1;
}

void *get_pointer(unsigned int offset)
{
	if (!offset)
		return NULL;

	return (node_t *)(((unsigned char*)heap.start) + offset - 1);
}

static unsigned char get_bin_index(unsigned int sz)
{
	unsigned char index = 0;
	sz = sz < 4 ? 4 : sz;

	while (sz >>= 1)
		index++;

	index -= 2;

	if (index > BIN_MAX_IDX)
		return BIN_MAX_IDX;

	return index;
}

static footer_t *get_foot(node_t *node)
{
	return (footer_t*)((unsigned char*)node + sizeof(node_t) + node->size);
}

static void create_foot(heap_t *heap, node_t *head)
{
	footer_t *foot = get_foot(head);
	foot->header = get_offset(head);
}

static void add_node(heap_t *heap, bin_t *bin, node_t *node)
{
	node_t *curr, *previous = NULL;

	node->next = 0;
	node->prev = 0;

	if (!bin->head) {
		bin->head = get_offset(node);
		return;
	}

	curr = get_pointer(bin->head);
	while (curr->size <= node->size) {
		if (!curr->next)
			break;

		previous = curr;
		curr = get_pointer(curr->next);
	}

	if (curr == NULL) {
		previous->next = get_offset(node);
		node->prev = get_offset(previous);
	} else {
		if (previous != NULL) {
			node->next = get_offset(curr);
			previous->next = get_offset(node);

			node->prev = get_offset(previous);
			curr->prev = get_offset(node);
		} else {
			node->next = bin->head;
			curr->prev = get_offset(node);
			bin->head = get_offset(node);
		}
	}
}

static void remove_node(heap_t *heap, bin_t * bin, node_t *node)
{
	node_t *temp, *prev, *next;

	if (!bin->head)
		return;

	temp = get_pointer(bin->head);
	if (temp == node) {
		bin->head = temp->next;
		return;
	}

	while (temp->next) {
		prev = temp;
		temp = get_pointer(temp->next);

		if (temp == node) {
			if (!temp->next) {
				prev->next = 0;
			} else {
				prev->next = temp->next;
				next = get_pointer(temp->next);
				next->prev = temp->prev;
			}

			return;
		}
	}
}

static node_t *get_best_fit(heap_t *heap, bin_t *bin, unsigned int size)
{
	node_t *temp;

	if (!bin->head)
		return NULL;

	temp = get_pointer(bin->head);

	while (temp != NULL) {
		if (temp->size >= size)
			return temp;

		temp = get_pointer(temp->next);
	}

	return NULL;
}

void reset_heap(void)
{
	unsigned char index;
	node_t *init_region;

	vs_memset(heap.bins, 0, BINS_SIZE);

	init_region = (node_t*)heap.start;
	init_region->hole = 1;
	init_region->size = heap.heap_size - sizeof(node_t) - sizeof(footer_t);

	create_foot(&heap, init_region);

	index = get_bin_index(init_region->size);

	add_node(&heap, heap.bins + index, init_region);
}

void init_heap(void *start, unsigned int heap_size)
{
	heap.heap_size = heap_size;
	heap.bins = start;
	heap.start = start + BINS_SIZE;
	heap.end = start + heap_size;
}

void *heap_alloc(unsigned int size)
{
	unsigned char index, new_idx;
	bin_t *temp;
	node_t *found = NULL, *split = NULL;

	if (heap.heap_size == 0)
		return NULL;

	/* make sure all addresses are aligned to 8 */
	if (size & 0x7) {
		size &= ~0x7;
		size += 0x8;
	}

	index = get_bin_index(size);

	while (index < BIN_COUNT) {
		temp = heap.bins + index;
		found = get_best_fit(&heap, temp, size);
		if (found)
			break;

		index++;
	}

	if (found == NULL)
		return NULL;

	if ((found->size - size) > (OVERHEAD + MIN_ALLOC_SZ)) {
		split = (node_t*)(((unsigned char*)found) + OVERHEAD + size);
		split->size = found->size - size - OVERHEAD;
		split->hole = 1;
		create_foot(&heap, split);

		found->size = size;
		create_foot(&heap, found);
	}

	found->hole = 0;
	remove_node(&heap, heap.bins + index, found);

	if (split) {
		new_idx = get_bin_index(split->size);
		add_node(&heap, heap.bins + new_idx, split);
	}

	found->prev = 0;
	found->next = 0;

	return ((unsigned char*)found) + sizeof(node_t);
}

void *heap_calloc(unsigned int size)
{
	void *ptr = heap_alloc(size);

	if (ptr)
		vs_memset(ptr, 0 , size);

	if ((unsigned long)ptr & 0x7) {
		cls_dbg("address is not aligned\n");
		heap_free(ptr);
		return NULL;
	}

	return ptr;
}

void heap_free(void *p)
{
	bin_t *list;
	footer_t *old_foot, *curr_foot;
	node_t *next, *prev;
	node_t *head = (node_t *)((unsigned char*)p - sizeof(node_t));

	/* for testing */
	vs_memset(p, 0, 4);

	if (head == heap.start) {
		head->hole = 1;
		add_node(&heap, heap.bins + get_bin_index(head->size), head);
		return;
	}

	next = (node_t *)((unsigned char*)p + head->size + sizeof(footer_t));
	curr_foot = (footer_t *)((unsigned char*)head - sizeof(footer_t));
	prev = get_pointer(curr_foot->header);

	if (prev->hole) {
		list = heap.bins + get_bin_index(prev->size);
		remove_node(&heap, list, prev);
		prev->size += OVERHEAD + head->size;
		create_foot(&heap, prev);
		head = prev;
	}

	if (next->hole) {
		list = heap.bins + get_bin_index(next->size);
		remove_node(&heap, list, next);
		head->size += OVERHEAD + next->size;
		old_foot = get_foot(next);
		old_foot->header = 0;
		next->size = 0;
		next->hole = 0;
		create_foot(&heap, head);
	}

	head->hole = 1;
	add_node(&heap, heap.bins + get_bin_index(head->size), head);
}

#ifdef CLS_DEBUG
void heap_print(void)
{
	unsigned int i, size = 0;
	bin_t *bin;
	node_t *temp;

//	cls_printf("heap allocator status:\n");
	for (i = 0; i < BIN_COUNT; i++) {
		bin = heap.bins + i;
//		cls_printf("bin %u: head 0x%x\n", i, bin->head);

		temp = get_pointer(bin->head);
		while (temp != NULL) {
//			cls_printf("  size %u, prev 0x%x, next 0x%x\n", temp->size, temp->prev, temp->next);
			if (temp->hole)
				size += temp->size;
			temp = get_pointer(temp->next);
		}
	}

	cls_printf("total free size: %u, out of %u bytes\n", size, (unsigned int)(heap.end - heap.start));
}
#endif
