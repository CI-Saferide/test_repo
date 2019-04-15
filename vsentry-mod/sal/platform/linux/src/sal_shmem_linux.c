#include "sal_linux.h"
#include "sr_shmem.h"
#include "sr_sal_common.h"

SR_32 sal_shmem_free(sr_shmem *sr_shmem_ptr)
{
	int i;

	if (!sr_shmem_ptr || !sr_shmem_ptr->buffer) {
		sal_kernel_print_err("wrong params: 0x%p, %p\n", sr_shmem_ptr, sr_shmem_ptr->buffer);
		return -1;
	}

	for (i = 0; i < sr_shmem_ptr->buffer_size; i+= PAGE_SIZE) {
		ClearPageReserved(virt_to_page(sr_shmem_ptr->buffer + i));
	}

	free_pages((unsigned long)sr_shmem_ptr->buffer, get_order(sr_shmem_ptr->buffer_size));

	sal_kernel_print_info("0x%p size 0x%08x is free\n", sr_shmem_ptr->buffer, sr_shmem_ptr->buffer_size);

	sr_shmem_ptr->buffer = NULL;
	sr_shmem_ptr->buffer_size = 0;

	return 0;
}

SR_32 sal_shmem_alloc(sr_shmem *sr_shmem_ptr, SR_32 length, SR_32 type)
{
	int i;
	void *buf;

	if (!sr_shmem_ptr || (length <= 0) || (length > MAX_BUFFER_SIZE)) {
		sal_kernel_print_err("wrong params: 0x%p, %d\n", sr_shmem_ptr, length);
		return -EIO;
	}

	buf = (void *)__get_free_pages(GFP_KERNEL, get_order(length));
	if (!buf) {
		sal_kernel_print_err("failed to alloc pages\n");
		return -ENOMEM;
	}
	memset(buf, 0, length);

	sr_shmem_ptr->buffer =  buf;
	sr_shmem_ptr->buffer_size = length;

	for (i = 0; i < get_order(length)*PAGE_SIZE; i+= PAGE_SIZE) {
		SetPageReserved(virt_to_page(sr_shmem_ptr->buffer + i));
	}

	//sal_kernel_print_info("sal_shmem_alloc allocated 0x%p size 0x%08x\n",
	//	sr_shmem_ptr->buffer, sr_shmem_ptr->buffer_size);

	return 0;
}

