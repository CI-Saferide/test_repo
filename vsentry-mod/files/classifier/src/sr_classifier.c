#include "multiplexer.h"
#include "sal_linux.h"
#include "sr_radix.h"

struct radix_head *sr_cls_src_ipv4;

void sr_classifier_ut(void) ;

int sr_classifier_init(void)
{
	if (!rn_inithead((void **)&sr_cls_src_ipv4, (8 * offsetof(struct sockaddr_in, sin_addr)))) {
		sal_kernel_print_alert("Error Initializing radix tree\n");
	} else {
		sal_kernel_print_alert("Successfully Initialized radix tree\n");
	}
	sr_classifier_ut();
	return 0;
}

void sr_classifier_uninit(void)
{
	if (sr_cls_src_ipv4) {
		rn_detachhead((void **)&sr_cls_src_ipv4);
		sr_cls_src_ipv4 = NULL;
	}
}

int sr_cls_add_ipv4(SR_U32 addr, SR_U32 netmask, int rulenum)
{
	struct radix_node *node = NULL;
	struct radix_node *treenodes = NULL;
	struct sockaddr_in *ip, *mask;

	treenodes = SR_ZALLOC(2*sizeof(struct radix_node));
	ip = SR_ZALLOC(sizeof(struct sockaddr_in));
	mask = SR_ZALLOC(sizeof(struct sockaddr_in));


	if (!treenodes) {
		return -1;
	}
	ip->sin_family = AF_INET;
	ip->sin_addr.s_addr = addr;
	//ip.sin_len = 32; // ????
	mask->sin_family = AF_INET;
	mask->sin_addr.s_addr = netmask;

	// TODO: store real bitmasks here. need to store on index 1
	treenodes[1].sr_private.magic = rulenum;

	node = rn_addroute((void*)ip, (void*)mask, sr_cls_src_ipv4, treenodes);
        return 0;
}

int sr_cls_find_ipv4(SR_U32 addr)
{
        struct radix_node *node = NULL;
        struct sockaddr_in *ip;

        ip = SR_ZALLOC(sizeof(struct sockaddr_in));


        if (!ip) {
                return -1;
        }
        ip->sin_family = AF_INET;
        ip->sin_addr.s_addr = addr;

        node = rn_match((void*)ip, sr_cls_src_ipv4);
        // TODO: match iterates and needs to collect the bits along the way
        return (node?0:-1);
}


void sr_classifier_ut(void)
{
        //sr_cls_add_ipv4(htonl(0x23232323), htonl(0xffffffff),10);
        //sr_cls_find_ipv4(htonl(0x23232323));
        sr_cls_add_ipv4(htonl(0x12121200), htonl(0xffffff00),30);
        sr_cls_find_ipv4(htonl(0x12121212));
        sr_cls_add_ipv4(htonl(0x12120000), htonl(0xffff0000),20);
        sr_cls_find_ipv4(htonl(0x12121212));
        sr_cls_add_ipv4(htonl(0x12121212), htonl(0xffffffff),40);
        sr_cls_find_ipv4(htonl(0x12121212));
}

