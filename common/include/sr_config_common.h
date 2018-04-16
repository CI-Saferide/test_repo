#ifndef SR_CONFIG_COMMON_H
#define SR_CONFIG_COMMON_H
#include "sr_types.h"

struct sr_config_msg {
	SR_U8 	cef_max_rate;
	SR_U8 	def_file_action;
	SR_U8 	def_can_action;
	SR_U8 	def_net_action;
};

#endif /* SR_CONFIG_COMMON_H */
