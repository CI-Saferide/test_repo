#include <linux/vsentry/vsentry.h>
#include "classifier.h"

int cls_handle_event(vsentry_ev_type_e ev_type, vsentry_event_t *event, bool atomic)
{
	int ret;

	if (likely(ev_type >= VSENTRY_FILE_EVENT))
		return cls_classify_event(ev_type, event, atomic);

	switch (ev_type) {
	case VSENTRY_CLASIFFIER_INIT:
		ret = cls_init(event);
		break;
#ifdef CLS_DEBUG
	case VSENTRY_REGISTER_PRINTF:
		cls_register_printf(event);
		ret = VSENTRY_SUCCESS;
		break;

	case VSENTRY_PRINT_INFO:
		cls_print_db();
		ret = VSENTRY_SUCCESS;
		break;
#endif

	case VSENTRY_CLASIFFIER_SET_MODE:
		ret = cls_set_mode(*(unsigned int*)event);
		break;

	default:
		cls_err("invalid event type\n");
		ret = VSENTRY_INVALID;
	}

	return ret;
}