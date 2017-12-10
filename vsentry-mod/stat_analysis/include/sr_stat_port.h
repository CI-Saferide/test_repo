#ifndef SR_STAT_PORT_H
#define SR_STAT_PORT_H

#include "sr_sal_common.h"
#include "sr_hash.h"

struct sr_hash_ent_stat_port_t{
        SR_U32 key;
        SR_U32 type;
        struct sr_hash_ent_t *next;
        SR_U32 pid;
};

SR_32 sr_stat_port_init(void);
void sr_stat_port_uninit(void);
void sr_stat_port_ut(void);

SR_32 sr_stat_port_update(SR_U16 port, SR_U32 pid);
SR_32 sr_stat_port_del(SR_U16 port);
SR_U32 sr_stat_port_find_pid(SR_U16 port);

#endif
