#include <linux/vsentry/vsentry.h>
#include "classifier.h"
#include "file_cls.h"

int cls_handle_event(vsentry_ev_type_e ev_type, vsentry_event_t *event)
{
	int ret;

	if (likely(ev_type >= VSENTRY_FILE_EVENT))
		return cls_classify_event(ev_type, event);

	switch (ev_type) {
	case VSENTRY_CLASIFFIER_INIT:
		ret = cls_init(event);
		break;
	case VSENTRY_CLASIFFIER_SET_MODE:
		ret = cls_set_mode(*(vsentry_mode_e*)event);
		break;
	case VSENTRY_CLASIFFIER_GET_MODE:
		*(vsentry_mode_e*)event = cls_get_mode();
		ret = VSENTRY_SUCCESS;
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

	case VSENTRY_REMOVE_INODE:
		file_cls_remove_inode((unsigned long*)event);
//		prog_cls_remove_inode((unsigned long*)event);
		ret = VSENTRY_SUCCESS;
		break;

	default:
		cls_err("invalid event type\n");
		ret = VSENTRY_INVALID;
	}

	return ret;
}
