#include "sr_can_collector.h"
#include "sal_linux.h"
#include "sr_sal_common.h"
#ifdef CONFIG_CAN_ML
#include "sr_ml_can.h"
#endif /* CONFIG_CAN_ML */
extern struct canTaskParams can_args;

const int timestamp_on = 1;
static __u32 dropcnt;

SR_32 can_collector_task(void *data)
{
    fd_set rdfs;
    struct sockaddr_can addr;
    time_t currtime;
    int nbytes;
    struct tm now;

    char buffer[128];
    char buffer_TS[64];
    char buffer_MsgID[64];
    char buffer_PAYLOAD[64];
    
    char ctrlmsg[CMSG_SPACE(sizeof(struct timeval)) + CMSG_SPACE(sizeof(__u32))];
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    struct canfd_frame frame;
    struct timeval *timeout_current = NULL;
    int ret;

    struct timeval tv;
	
    localtime_r(&currtime,&now);

    iov.iov_base = &frame;
    msg.msg_name = &addr;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &ctrlmsg;

    /* send frame */

    memset(&frame, 0, sizeof(frame));
    frame.can_id = 0x123;
    frame.len = 8;
    frame.flags = 0;
    frame.data[0] = 0xde;
    frame.data[1] = 0xed;
    frame.data[2] = 0xbe;
    frame.data[3] = 0xef;
    frame.data[4] = 0xde;
    frame.data[5] = 0xed;
    frame.data[6] = 0xbe;
    frame.data[7] = 0xef;
    
    nbytes = write(can_args.can_fd, &frame, CAN_MTU);
	
	while (!sr_task_should_stop(SR_CAN_COLLECT_TASK)) {
	
		FD_SET(can_args.can_fd,&rdfs);

        if ((ret = select(can_args.can_fd + 1, &rdfs, NULL, NULL, timeout_current)) <= 0) {
            sleep(1);
            continue;
        }
        if (FD_ISSET(can_args.can_fd,&rdfs)) {
            int i;

            /* these settings may be modified by recvmsg() */
            iov.iov_len = sizeof(frame);
            msg.msg_namelen = sizeof(addr);
            msg.msg_controllen = sizeof(ctrlmsg);
            msg.msg_flags = 0;

            nbytes = recvmsg(can_args.can_fd, &msg, 0);
            if(nbytes < 0) return SR_ERROR;

            for (cmsg = CMSG_FIRSTHDR(&msg); cmsg && (cmsg->cmsg_level == SOL_SOCKET); cmsg = CMSG_NXTHDR(&msg, cmsg)) 
            {
                if (cmsg->cmsg_type == SO_TIMESTAMP)
                    memcpy(&tv, CMSG_DATA(cmsg), sizeof(tv));
                else if (cmsg->cmsg_type == SO_RXQ_OVFL)
                    memcpy(&dropcnt, CMSG_DATA(cmsg), sizeof(__u32));
            }
					struct tm tm;
					char timestring[25];
					tm = *localtime(&tv.tv_sec);
					strftime(timestring, 24, "%Y-%m-%d %H:%M:%S", &tm);
					sprintf(buffer_TS,"(%s.%06ld) ", timestring, tv.tv_usec);
					
					
			strcpy(buffer,buffer_TS);

            sal_sprintf(buffer_MsgID,"%9x [%d]",frame.can_id, frame.len); //buffer for MsgID and size

			strcat(buffer,buffer_MsgID);

            for (i = 0; i < frame.len; i++) {
                sal_sprintf(buffer_PAYLOAD," %02x",frame.data[i]); //buffer for payload
                strcat(buffer,buffer_PAYLOAD);
            }            
            strcat(buffer,"\n");
#ifdef CONFIG_CAN_ML
            /* send raw can to ml */
			ml_can_get_raw_data((SR_U64)((tv.tv_sec * 1000000) + tv.tv_usec), (SR_U32)frame.can_id);
#endif /* CONFIG_CAN_ML */

            log_it(buffer);
#ifdef SR_CAN_DEBUG_PRINT
            if(can_args.can_print)
				printf("%s",buffer);
#endif
		}	
	}
    close(can_args.can_fd);
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
		"CAN collector ended\n");

	return SR_SUCCESS;
}

SR_32 init_can_socket(SR_8 *interface) 
{
  SR_32 can_fd;
  struct sockaddr_can addr = {};
  struct ifreq ifr;
  const SR_32 timestamp_on = 1;
  const SR_32 canfd_on = 1;

  if ((can_fd = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
      perror("socket");
      return SR_ERROR;
  }
  addr.can_family = AF_CAN;

  memset(&ifr.ifr_name, 0, sizeof(ifr.ifr_name));
  strncpy(ifr.ifr_name, interface, strlen(interface));
  if (strncmp("any", ifr.ifr_name, strlen("any"))) {
     if (ioctl(can_fd, SIOCGIFINDEX, &ifr) < 0) {
         perror("SIOCGIFINDEX");
         return SR_ERROR;
     }
     addr.can_ifindex = ifr.ifr_ifindex;
  } else
    addr.can_ifindex = 0; /* any can interface */

  /* try to switch the socket into CAN FD mode */
  setsockopt(can_fd, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &canfd_on, sizeof(canfd_on));
  if (setsockopt(can_fd, SOL_SOCKET, SO_TIMESTAMP,
      &timestamp_on, sizeof(timestamp_on)) < 0) {
      perror("setsockopt SO_TIMESTAMP");
      return SR_ERROR;
   }
   if (bind(can_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
       perror("bind");
       return SR_ERROR;
   }

   return can_fd;
}





