#ifndef SR_CLS_FILTER_PATH_
#define SR_CLS_FILTER_PATH_
#include "sr_types.h"

#define SR_MAX_FILTER_PATH_LEN 128

enum {
	SR_CLS_FILTER_PATH_ADD,
	SR_CLS_FILTER_PATH_REMOVE,
	SR_CLS_FILTER_PATH_MAX = SR_CLS_FILTER_PATH_REMOVE,
	SR_CLS_FILTER_PATH_TOTAL = (SR_CLS_FILTER_PATH_MAX + 1),
};

struct sr_cls_filter_path_msg {
	SR_U8 msg_type;
	char  path[SR_MAX_FILTER_PATH_LEN];	
};

#endif /* SR_CLS_FILEFR_PATH_H */
