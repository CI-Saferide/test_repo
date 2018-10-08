#ifndef __SAL_THIRD_PARTY_INTERFACE_H__
#define __SAL_THIRD_PARTY_INTERFACE_H__

#include "sr_types.h"

#define SR_THIRD_PARTY_FILE "/tmp/sr_engine.socket"

SR_32 sal_third_party_interface_init(void);
void sal_third_party_interface_uninit(void);

#endif
