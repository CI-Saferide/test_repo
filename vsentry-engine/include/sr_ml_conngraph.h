#ifndef SR_ML_CONNGRAPH_H
#define SR_ML_CONNGRAPH_H
#include "sr_ec_common.h"

SR_32 sr_ml_conngraph_init(void);
SR_32 sr_ml_conngraph_clear_graph(void);
void sr_ml_conngraph_save(void);
void sr_ml_conngraph_loadconf(void);
void sr_ml_conngraph_event( struct sr_ec_new_connection_t *pNewConnection);
void sr_ml_conngraph_print_tree(void);
#endif
