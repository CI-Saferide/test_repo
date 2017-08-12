#include "sr_sal_common.h"
#include "sr_event_receiver.h"
#include "sr_radix.h"
#include <netinet/in.h>
#include "sr_ml_conngraph.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>



struct radix_head *sr_ml_conngraph_table;

void sr_ml_conngraph_print_tree(void); 


SR_32 sr_ml_conngraph_init(void)
{
	if (!rn_inithead((void **)&sr_ml_conngraph_table, (8 * offsetof(struct sockaddr_in, sin_addr)))) {
		printf("Error initializing conngraph\n");
		return (SR_ERROR);
	}
	return SR_SUCCESS;
}

SR_32 sr_ml_conngraph_clear_graph(void)
{
	if (!rn_detachhead((void **)&sr_ml_conngraph_table)) {
		printf("Error clearing conngraph\n");
	}
	return sr_ml_conngraph_init();
}

void sr_ml_conngraph_event( struct sr_ec_new_connection_t *pNewConnection)
{
	struct radix_node *treenodes = NULL;
	struct sockaddr_in *ip=NULL;
	struct radix_node *node;

	ip = calloc(1, sizeof(struct sockaddr_in));
	if (!ip) {
		return;
	}
	ip->sin_family = AF_INET;
	ip->sin_addr.s_addr = pNewConnection->remote_addr.v4addr;

	node = rn_lookup((void*)ip, NULL, sr_ml_conngraph_table);
	
	switch (sr_ml_mode) {
		case ML_MODE_LEARN:
			if (node) {
				free(ip);
				return;
			}
			treenodes = calloc(1, 2*sizeof(struct radix_node));
			if (!treenodes) {
				free(ip);
				return;
			}
			rn_addroute((void*)ip, NULL, sr_ml_conngraph_table, treenodes);
			break;
		case ML_MODE_DETECT:
			free(ip);
			if (!node) { // detected connection to unknown destination
				printf("LOG: detected suspicious connection to %x[%d]\n", pNewConnection->remote_addr.v4addr, pNewConnection->dport); // TODO: this needs to be properly logged
			}
			
		default:
			break;
	}

	//sr_ml_conngraph_print_tree();
}

int sr_ml_node_printer(struct radix_node *node, void *unused)
{ 
	struct sockaddr_in *ip=(struct sockaddr_in *)(node->rn_u.rn_leaf.rn_Key);
	printf("Node: %x\n", ip->sin_addr.s_addr);
	return 0;
}

void sr_ml_conngraph_print_tree(void)
{
	rn_walktree(sr_ml_conngraph_table, sr_ml_node_printer, NULL);
}


int sr_ml_node_save(struct radix_node *node, void *fd)
{ 
	struct sockaddr_in *ip=(struct sockaddr_in *)(node->rn_u.rn_leaf.rn_Key);
	char c;

	c=4; // ipv4/ipv6
	if (write((int)*(int*)fd, &c, 1) != 1) { 
		printf("Failed to write to conngraph conf file!\n");
		return -1;
	}
	if (write((int)*(int*)fd, &ip->sin_addr.s_addr, 4) != 4) {
		printf("Failed to write to conngraph conf file!\n");
		return -1;
	}
	return 0;
}

void sr_ml_conngraph_save(void)
{
	int fd;
	
	fd = open(SR_CONNGRAPH_CONF_FILE,  O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);

	if (fd < 0) {
		printf("Failed to open conngraph conf file!\n");
		return;
	}
	rn_walktree(sr_ml_conngraph_table, sr_ml_node_save, (void *)&fd);

	close(fd);
	printf("Successfully saved conngraph conf file\n");

}

void sr_ml_conngraph_loadconf(void)
{
	int fd;
	char c, ret;
	struct sockaddr_in *ip=NULL;
	struct radix_node *node;
	struct radix_node *treenodes = NULL;
	
	fd = open(SR_CONNGRAPH_CONF_FILE,  O_RDONLY);

	if (fd < 0) {
		printf("Failed to read conngraph conf file!\n");
		return;
	}
	while (1) {
		ret = read(fd, &c, 1);
		if (ret < 0) {
			printf("failed to read IP version\n");
			close(fd);
			return;
		}
		if (ret == 0) { // EOF
			close(fd);
			return;
		}
		if (c != 4) {
			printf("Invalid IP version\n");
			close(fd);
			return;
		}
		ip = calloc(1, sizeof(struct sockaddr_in));
		if (!ip) {
			close(fd);
			return;
		}
		ip->sin_family = AF_INET;
		if (read(fd, &ip->sin_addr.s_addr, 4) != 4) {
			printf("Failed to read IP address\n");
			close(fd);
			return;
		}
		node = rn_lookup((void*)ip, NULL, sr_ml_conngraph_table);
		if(node) {
			printf("Address %x already in tree\n", ip->sin_addr.s_addr);
			free(ip);
			continue;
		}
		treenodes = calloc(1, 2*sizeof(struct radix_node));
		if (!treenodes) {
			free(ip);
			close(fd);
			return;
		}
		rn_addroute((void*)ip, NULL, sr_ml_conngraph_table, treenodes);
	}

	close(fd);
	printf("Successfully read conngraph conf file\n");

}
