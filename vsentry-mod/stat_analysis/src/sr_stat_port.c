#include "dispatcher.h"
#include "sal_linux.h"
#include "sr_hash.h"
#include "sr_stat_port.h"

struct sr_hash_table_t *sr_stat_port_table;

#define STST_PORT_HASH_TABLE_SIZE 512

SR_32 sr_stat_port_update(SR_U16 port, SR_U32 pid)
{
	struct sr_hash_ent_stat_port_t *ent;

	if (!sr_stat_port_table)
		return SR_ERROR;

	if ((ent = (struct sr_hash_ent_stat_port_t *)sr_hash_lookup(sr_stat_port_table, (SR_32)port))) {
		ent->pid = pid;
	    	return SR_SUCCESS;
        }
        ent = SR_ZALLOC(sizeof(*ent));
	if (!ent) {
	    sal_kernel_print_alert("Error: Failed to allocate memory\n");
	    return SR_ERROR;
        }

        ent->key = (SR_32)port;
        ent->pid = pid;
	sr_hash_insert(sr_stat_port_table, ent);

	return SR_SUCCESS;
}

SR_32 sr_stat_port_del(SR_U16 port)
{
	if (sr_stat_port_table)
		sr_hash_delete(sr_stat_port_table, (SR_32)port);

	return SR_SUCCESS;
}

// Returns inode of executable
SR_U32 sr_stat_port_find_pid(SR_U16 port)
{
	struct sr_hash_ent_stat_port_t *ent=(struct sr_hash_ent_stat_port_t *)sr_hash_lookup(sr_stat_port_table, (SR_32)port);

	if (!ent)
 	    return 0;
	
	return ent->pid;
}

int sr_stat_port_init(void)
{
	sr_stat_port_table = sr_hash_new_table(STST_PORT_HASH_TABLE_SIZE);
	if (!sr_stat_port_table) {
		sal_kernel_print_alert("Failed to allocate hash table!\n");
		return SR_ERROR;
	}
	sal_kernel_print_alert("Successfully initialized process table!\n");

	return SR_SUCCESS;
}

void sr_stat_port_uninit(void)
{ 
	SR_U32 i;
	struct sr_hash_ent_t *curr, *next;
	
	if (!sr_stat_port_table)
		return;

	for(i = 0; i < STST_PORT_HASH_TABLE_SIZE; i++) {
		if (sr_stat_port_table->buckets[i].head != NULL){
			sal_printf("hash_index[%d] - DELETEING\n",i);
			curr = sr_stat_port_table->buckets[i].head;				
			while (curr != NULL){
				sal_printf("\t\tDelete port : %u\n",curr->key);
				next = curr->next;
				SR_FREE(curr);
				curr= next;
			}
		}
	}

	if(sr_stat_port_table->buckets != NULL){
		SR_FREE(sr_stat_port_table->buckets);
	}
	SR_FREE(sr_stat_port_table);
	sr_stat_port_table = NULL;
	sal_printf("[%s]: Successfully removed stat portr hash!\n", MODULE_NAME);
}

#ifdef UNIT_TEST
void sr_stat_port_ut(void)
{
	int st;

	if ((st = sr_stat_port_update(7777, 1234)) != SR_SUCCESS) {
 	    printk("*** Error update port!!\n");
	    return;
	}
        printk("The pid of the port expect:1234 :%d \n", sr_stat_port_find_pid(7777));
	if ((st = sr_stat_port_update(7788, 4567)) != SR_SUCCESS) {
 	    printk("*** Error update port!!\n");
	    return;
	}
        printk("The pid expect:4567 :%d \n", sr_stat_port_find_pid(7788));
	if ((st = sr_stat_port_update(7777, 2424)) != SR_SUCCESS) {
 	    printk("*** Error update port!!\n");
	    return;
	}
        printk("The pid of the port expect:2424 :%d \n", sr_stat_port_find_pid(7777));
}
#endif /* UNIT_TEST */
