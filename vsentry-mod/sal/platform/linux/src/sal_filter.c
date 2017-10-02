/* file: sal_filter.c
 * purpose: this file implements the sal filter engine
*/

#include "sal_linux.h"
#include "sr_sal_common.h"
#include <linux/list.h>

static struct list_head filter_paths_list;

struct filter_path {
  char *path;
  struct list_head list;
};

SR_32 sal_filter_path_init(void)
{
	INIT_LIST_HEAD(&filter_paths_list);
 		
	return SR_SUCCESS;
}

SR_32 sal_filter_path_add(char *path)
{
	struct filter_path *new_item;

	if (!(new_item = vmalloc(sizeof(struct filter_path))))
    		return SR_ERROR;
	if (!(new_item->path = vmalloc(strlen(path) + 1))) {
		vfree(new_item);
		return SR_ERROR;
	}
	strcpy(new_item->path, path);
	list_add_tail(&(new_item->list), &filter_paths_list);

	return SR_SUCCESS;
}

SR_32 sal_filter_path_del(char *path)
{
	struct filter_path *entry;
	struct list_head *p, *n;

	list_for_each_safe(p, n, &filter_paths_list) {
		entry = list_entry(p, struct filter_path, list);
		if (!strcmp(path, entry->path)) {
			list_del(p);
			vfree(entry->path);
			vfree(entry);
		}
	}

	return SR_SUCCESS;
}

SR_BOOL sal_filter_path_is_match(char *path)
{
	SR_BOOL is_match = SR_FALSE;
	struct filter_path *entry;
	int prefix_len;
 
	list_for_each_entry(entry, &filter_paths_list, list) {
		prefix_len = strlen(entry->path);
		if (prefix_len <= strlen(path) && !memcmp(path, entry->path, prefix_len)) {
			is_match = SR_TRUE;
			break;
		}
	}

	return is_match;
}

SR_32 sal_filter_path_print(void)
{
	struct filter_path *entry;

	list_for_each_entry(entry, &filter_paths_list, list) {
		printk("*** path :%s \n", entry->path);
	}

	return SR_SUCCESS;
}

void sal_filter_path_deinit(void)
{
	struct filter_path *entry;
	struct list_head *p, *n;

	list_for_each_safe(p, n, &filter_paths_list) {
		entry = list_entry(p, struct filter_path, list);
		list_del(p);
		vfree(entry->path);
		vfree(entry);
	}
}
