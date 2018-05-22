#ifndef SR_CONTROL_H
#define SR_CONTROL_H

#include "sr_types.h"

SR_32 sr_control_set_state(SR_BOOL state);
SR_32 sr_control_util(sr_control_verb_t control_type);
SR_32 sr_control_set_mem_opt(cls_file_mem_optimization_t mem_opt);

#endif /* SR_CONTROL_H */
