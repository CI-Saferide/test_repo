#include "act.h"
#include "aux.h"
#include "heap.h"
#include "classifier.h"

#ifdef ACT_DEBUG
#define act_dbg cls_dbg
#define act_err cls_err
#else
#define act_dbg(...)
#define act_err(...)
#endif

/* action list item */
typedef struct __attribute__ ((packed, aligned(8))) {
	act_t 		action;
	unsigned int 	next_offset;
	unsigned int 	ref_count;
} act_list_item_t;

/* action list head */
static act_list_item_t *list_head = NULL;
unsigned int *db_offset = NULL;

/* action db init function */
int action_cls_init(unsigned int *head_offset)
{
	db_offset = head_offset;

	if (*head_offset)
		list_head = get_pointer(*head_offset);

	return VSENTRY_SUCCESS;
}

static bool action_cls_compare(act_t *candidat, char *act_name, int search_len)
{
	if (!candidat || !act_name)
		return false;

	if (candidat->name_len != search_len)
		return false;

	if (vs_memcmp(candidat->name, act_name, search_len) == 0)
		return true;

	return false;
}

int action_cls_add(act_t *act)
{
	act_list_item_t *item = list_head, *prev = NULL;

	if (!act || !act->name || !act->name_len)
		return VSENTRY_INVALID;

	if (!list_head) {
		/* the list is empty */
		list_head = heap_calloc(sizeof(act_list_item_t));
		if (!list_head) {
			act_err("failed to allocate action\n");
			return VSENTRY_ERROR;
		}

		vs_memcpy(&list_head->action, act, sizeof(act_t));

		/* update the main db */
		*db_offset = get_offset(list_head);

		act_dbg("created new action %s: ", list_head->action.name);
		action_print_act(&list_head->action);

		return VSENTRY_SUCCESS;
	}

	while (item) {
		if (action_cls_compare(&item->action, act->name, act->name_len)) {
			/* we found existing action .. just update it */
			act_dbg("updating action %s\n", item->action.name);
			vs_memcpy(&item->action, act, sizeof(act_t));
			return VSENTRY_SUCCESS;
		}

		prev = item;
		item = get_pointer(item->next_offset);
	}

	item = heap_calloc(sizeof(act_list_item_t));
	if (!item) {
		act_err("failed to allocate action\n");
		return VSENTRY_ERROR;
	}

	vs_memcpy(&item->action, act, sizeof(act_t));

	act_dbg("created new action %s: ", item->action.name);
	action_print_act(&item->action);

	if (prev)
		prev->next_offset = get_offset(item);

	return VSENTRY_SUCCESS;
}

int action_cls_del(char *act_name, int name_len)
{
	act_list_item_t *item = list_head, *prev = NULL;

	if (!act_name || name_len)
		return VSENTRY_INVALID;

	while (item) {
		if (action_cls_compare(&item->action, act_name, name_len))
			break;

		prev = item;
		item = get_pointer(item->next_offset);
	}

	if (!item)
		return VSENTRY_NONE_EXISTS;

	if (item->ref_count) {
		act_dbg("action %s is still refed %u\n", item->ref_count);
		return VSENTRY_SUCCESS;
	}

	if (prev)
		prev->next_offset = item->next_offset;

	act_dbg("deleting action %s: ", item->action.name);
	action_print_act(&item->action);

	heap_free(item);

	return VSENTRY_SUCCESS;
}

int action_cls_ref(bool ref, char *act_name, int name_len)
{
	act_list_item_t *item = list_head;

	if (!act_name || !vs_strlen(act_name))
		return VSENTRY_INVALID;

	while (item) {
		if (action_cls_compare(&item->action, act_name, name_len))
			break;

		item = get_pointer(item->next_offset);
	}

	if (!item)
		return VSENTRY_NONE_EXISTS;

	if (ref)
		item->ref_count++;
	else if (item->ref_count)
		item->ref_count--;

	act_dbg("action %s is refed %u times\n", item->action.name, item->ref_count);

	return VSENTRY_SUCCESS;
}

act_t *action_cls_search(char *act_name, int name_len)
{
	act_list_item_t *item = list_head;

	while (item) {
		if (action_cls_compare(&item->action, act_name, name_len))
			return &item->action;

		item = get_pointer(item->next_offset);
	}

	return NULL;
}

/* print act item content */
void action_print_act(act_t *act)
{
	if (!act)
		return;

	if (act->action_bitmap & VSENTRY_ACTION_ALLOW)
		cls_printf("allow ");
	else
		cls_printf("drop ");

	if (act->action_bitmap & VSENTRY_ACTION_LOG)
		cls_printf("log ");

	cls_printf("\n");
}

void action_print_list(void)
{
	act_list_item_t *item = list_head;

	cls_printf("action list:\n");

	while (item) {
		cls_printf("  action %s [ref %u]: ", item->action.name, item->ref_count);
		action_print_act(&item->action);
		item = get_pointer(item->next_offset);
	}

	cls_printf("\n");
}
