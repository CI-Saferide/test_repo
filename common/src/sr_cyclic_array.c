#include "sr_cyclic_array.h"
#include "sr_types.h"
#include "sr_sal_common.h"

#define CYCLIC_INC(i, size) (i < size - 1) ? (i + 1) : 0

void sr_cyclic_array_init(sr_cyclic_array_t *ca, void **arr, SR_U32 size)
{
	ca->arr = arr;
	ca->r = -1;
	ca->w = -1;
	ca->size = size;
}

SR_32 sr_cyclic_array_read(sr_cyclic_array_t *ca, void **val)
{
	if (ca->r == ca->w)
		return SR_ERROR; // Nothig to read.
	if (ca->r == -1)
		ca->r = 0;
	*val = ca->arr[ca->r];
  	ca->r = CYCLIC_INC(ca->r, ca->size);

	return SR_SUCCESS;
}

SR_32 sr_cyclic_array_write(sr_cyclic_array_t *ca, void *val)
{
	SR_U32 new_w;

	if (ca->w == -1)
		ca->w = 0;
	new_w = CYCLIC_INC(ca->w, ca->size);

	if (new_w == ca->r || (new_w == 0 && ca->r == -1))
		return SR_ERROR; // No more spacve

	ca->arr[ca->w] = val;
	ca->w = new_w;

	return SR_SUCCESS;
}

SR_BOOL sr_cyclic_array_is_full(sr_cyclic_array_t *ca)
{
	SR_U32 new_w = CYCLIC_INC(ca->w, ca->size);

	if (ca->w == -1)
		return SR_FALSE;
	if (new_w == ca->r || (new_w == 0 && ca->r == -1))
		return SR_TRUE;
	return SR_FALSE;
}
