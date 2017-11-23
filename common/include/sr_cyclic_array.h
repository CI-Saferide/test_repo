#ifndef __CYCLIC_ARRAY_H_
#define __CYCLIC_ARRAY_H_

#include "sr_types.h"

typedef struct sr_cyclic_array {
	void **arr;
	SR_U32 size;
	SR_32 r;
	SR_32 w;
} sr_cyclic_array_t;

void sr_cyclic_array_init(sr_cyclic_array_t *ca, void **arr, SR_U32 size);
SR_32 sr_cyclic_array_read(sr_cyclic_array_t *ca, void **val); 
SR_32 sr_cyclic_array_write(sr_cyclic_array_t *ca, void *val); 
SR_BOOL sr_cyclic_array_is_full(sr_cyclic_array_t *ca);

#endif 
