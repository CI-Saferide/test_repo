#ifndef __HEAP_H__
#define __HEAP_H__

#include <stdbool.h>

#define MIN_ALLOC_SZ 4
#define BIN_COUNT 9
#define BIN_MAX_IDX (BIN_COUNT - 1)
#define BINS_SIZE (BIN_COUNT * sizeof(bin_t))

typedef struct {
	unsigned int head;
	unsigned int pad;  /* this pas will make sure all addresses are aligned to 8 */
} bin_t;

typedef struct {
	void  	*start;
	void  	*end;
	bin_t 	*bins;
	int 	heap_size;
} heap_t;

void  init_heap(void *start, unsigned int heap_size);
void  reset_heap(void);
void *heap_alloc(unsigned int size);
void *heap_calloc(unsigned int size);
void  heap_free(void *p);
void *get_pointer(unsigned int offset);
unsigned int get_offset(void *p);
void  heap_print(void);

#endif /* __HEAP_H__ */
