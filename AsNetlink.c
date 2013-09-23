////////////////////////////////////////////////////////////////////////////////
//
//  File          : AsNetlink.c
//  Description   : The AsNetlink module implements a interface communicating
//			with the Linux kernel using netlink
//
//  Author  : Dave Tian
//  Created : Thu Aug 9 2013
//

// Includes
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>

// Project Includes
#include "AsNetlink.h"
#include "AsKrnRelay.h"
#include "AsControl.h"
#include "AsLog.h"

// Defines
struct sockaddr_nl arpsec_nl_addr;
struct sockaddr_nl arpsec_nl_dest_addr;
pid_t arpsec_pid;
int arpsec_sock_fd;
int asn_operating_mode;


// Module methods
////////////////////////////////////////////////////////////////////////////////
//
// Function     : asnInitNetlink
// Description  : Init the netlink socket (mode is sym vs. kernel)
//
// Inputs       : the kind of "mode" to operate in SIM vs. REAL
// Outputs      : 0 if successful, -1 if not

int asnInitNetlink(int mode)
{
	// Set the mode appropriately
	if ((mode != ASKRN_SIMULATION) && (mode != ASKRN_RELAY))
	{
		asLogMessage("Error on arpsecd mode [%d], aborting", mode);
		return -1;
	}
	asn_operating_mode = mode;

	// Return success for simulation mode
	if (mode == ASKRN_SIMULATION)
		return 0;

	// Fall into the real mode

	// Open the netlink socket
	arpsec_sock_fd = socket(PF_NETLINK, SOCK_RAW, ARPSEC_NETLINK);
	if (arpsec_sock_fd == -1)
	{
		asLogMessage("Error on netlink socket [%s], aborting", strerror(errno));
		return -1;
	}

	// Bind the socket
	memset(&arpsec_nl_addr, 0, sizeof(arpsec_nl_addr));
	arpsec_nl_addr.nl_family = AF_NETLINK;
	arpsec_pid = getpid();
	asLogMessage("Info: arpsecd pid [%u]", arpsec_pid);
	arpsec_nl_addr.nl_pid = arpsec_pid;
	if (bind(arpsec_sock_fd, (struct sockaddr*)&arpsec_nl_addr, sizeof(arpsec_nl_addr)) == -1)
	{
		asLogMessage("Error on netlink bind [%s], aborting", strerror(errno));
		return -1;
	}

	// Setup the netlink destination socket address
	memset(&arpsec_nl_dest_addr, 0, sizeof(arpsec_nl_dest_addr));
	arpsec_nl_dest_addr.nl_family = AF_NETLINK;
	arpsec_nl_dest_addr.nl_pid = 0;
	arpsec_nl_dest_addr.nl_groups = 0;

	asLogMessage("Info: netlink socket init done");
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : asnShutdownNetlink
// Description  : Close the netlink
//
// Inputs       : none
// Outputs      : 0 if successful, -1 if not

int asnShutdownNetlink(void)
{
	if (asn_operating_mode == ASKRN_RELAY)
	{
		if (arpsec_sock_fd != 0)
			close(arpsec_sock_fd);
	}

	asLogMessage("Info: netlink socket close done");
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : asnTestNetlink
// Description  : Test the bidirection netlink by sending/recving to/from the kernel
//
// Inputs       : void
// Outputs      : void

void asnTestNetlink(void)
{
	struct nlmsghdr *nlh;
	struct iovec iov;
	struct msghdr msg;
	int rtn;

	// Init the stack struct to avoid potential error
	memset(&iov, 0, sizeof(iov));
	memset(&msg, 0, sizeof(msg));

	// Create the nelink msg
	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(arpsec_nlmsg)));
	memset(nlh, 0, NLMSG_SPACE(sizeof(arpsec_nlmsg)));
	nlh->nlmsg_len = NLMSG_SPACE(sizeof(arpsec_nlmsg));
	nlh->nlmsg_pid = arpsec_pid;
	nlh->nlmsg_flags = 0;

	// Nothing to do for test msg - it is already what it is
	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_name = (void *)&arpsec_nl_dest_addr;
	msg.msg_namelen = sizeof(arpsec_nl_dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	// Send the msg to the kernel
	rtn = sendmsg(arpsec_sock_fd, &msg, 0);
	if (rtn == -1)
	{
		asLogMessage("asnTestNetlink: Error on sending netlink test msg to the kernel [%s]",
				strerror(errno));
		free(nlh);
		return;
	}
	asLogMessage("asnTestNetlink: Info - send netlink test msg to the kernel");

	// Recv the response from the kernel
	rtn = recvmsg(arpsec_sock_fd, &msg, 0);
	if (rtn == -1)
	{
		asLogMessage("asnTestNetlink: Error on recving netlink test msg from the kernel [%s]",
				strerror(errno));
		free(nlh);
		return;
	}
	asLogMessage("asnTestNetlink: Info - got netlink test msg from the kernel [%s]",
			NLMSG_DATA(nlh));
	free(nlh);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : asnGenArpReqStruct
// Description  : Generate the arpreq struct based on askRelayMessage
//
// Inputs       : arpReq_ptr - arpreq struct pointer
// Outputs      : 0 if successful, -1 if not

int asnGenArpReqStruct(askRelayMessage *msg_ptr, struct arpreq *arpReq_ptr, int opcode)
{
	// Defensive checking
	if ((msg_ptr->op != RFC_826_ARP_RES) &&
		(msg_ptr->op != RFC_903_ARP_RRES))
	{
		asLogMessage("asnGenArpReqStruct: Error on unsupported msg opcode [%d]",
				msg_ptr->op);
		return -1;
	}

	struct sockaddr_in *sa;
	char ip[ARPSEC_NETLINK_STR_IPV4_LEN] = {0};
	char mac[ARPSEC_NETLINK_STR_MAC_LEN] = {0};
	sa = (struct sockaddr_in *)&(arpReq_ptr->arp_pa);

	// Get the IPv4 and MAC address
	if (msg_ptr->op == RFC_826_ARP_RES)
	{
		asnLogicIpToStringIp(msg_ptr->target.network, ip);
		asnLogicMacToStringMac(msg_ptr->binding.media, mac);
	}
	else
	{
		asnLogicIpToStringIp(msg_ptr->binding.network, ip);
		asnLogicMacToStringMac(msg_ptr->target.media, mac);
	}

	asLogMessage("asnGenArpReqStruct: Info - ip=[%s], mac=[%s]", ip, mac);

	// Set the IPv4 address
	sa->sin_family = AF_INET;
	inet_pton(AF_INET, ip, &(sa->sin_addr));

	// Set the defalut device name
	strncpy(arpReq_ptr->arp_dev, ARPSEC_IF_NAME, sizeof(arpReq_ptr->arp_dev)-1);

	// Set up the hardware info only for bind
	if (opcode == ARPSEC_NETLINK_OP_BIND)
	{
		// Set the MAC address
		if (asn_mac_pton(mac, arpReq_ptr->arp_ha.sa_data) == -1)
		{
			asLogMessage("asnGenArpReqStruct: Error on asn_mac_pton()");
			return -1;
		}
	
		// Set the ARP protocol hardware identifier
		arpReq_ptr->arp_ha.sa_family = ARPHRD_ETHER;

		// Set the ARP entry flag
		arpReq_ptr->arp_flags = ATF_COM;
	}

	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : asnGenArpMsgStruct
// Description  : Generate the arpmsg struct based on askRelayMessage
//
// Inputs       : arpMsg_ptr - arpmsg struct pointer
// Outputs      : 0 if successful, -1 if not

int asnGenArpMsgStruct(askRelayMessage *msg_ptr, arpsec_arpmsg *arpMsg_ptr)
{
        // Defensive checking
        if ((msg_ptr->op != RFC_826_ARP_REQ) &&
                (msg_ptr->op != RFC_903_ARP_RREQ))
        {
                asLogMessage("asnGenArpMsgStruct: Error on unsupported msg opcode [%d]",
                                msg_ptr->op);
                return -1;
        }

	// Note: the first 4 members of arpmsg will be ignored
	// as the kernel changes do not care about them except
	// dev_ptr, ar_op, ar_sip, ar_sha, ar_tip, ar_tha. The key
	// is to construct the right format of the ARP/RARP reply
	// cause the kernel will create and send the reply directly
	// without considering if the src from the REQ should be
	// the target....
	// daveti Aug 14, 2013

        char ip[ARPSEC_NETLINK_STR_IPV4_LEN] = {0};
        char mac[ARPSEC_NETLINK_STR_MAC_LEN] = {0};

	// Set the opcode
	if (msg_ptr->op == RFC_826_ARP_REQ)
		arpMsg_ptr->ar_op[ARPSEC_ARP_16BIT-1] = ARPSEC_ARPOP_REPLY;
	else
		arpMsg_ptr->ar_op[ARPSEC_ARP_16BIT-1] = ARPSEC_ARPOP_RREPLY;

	// Set the sender IP/MAC using local info
	// This works for both REP/RREP
	asnLogicIpToStringIp(ascGetLocalNet(), ip);
	asnLogicMacToStringMac(ascGetLocalMedia(), mac);
	asLogMessage("asnGenArpMsgStruct: Info - sender: ip=[%s], mac=[%s]", ip, mac);

	inet_pton(AF_INET, ip, arpMsg_ptr->ar_sip);
	if (asn_mac_pton(mac, arpMsg_ptr->ar_sha) == -1)
	{
		asLogMessage("asnGenArpMsgStruct: Error on asn_mac_pton() for sender");
		return -1;
	}

	// Set the target IP/MAC from REQ/RREQ sender's IP/MAC
	// This works for both REP/RREP
	memset(ip, 0, ARPSEC_NETLINK_STR_IPV4_LEN);
	memset(mac, 0, ARPSEC_NETLINK_STR_MAC_LEN);
        asnLogicIpToStringIp(msg_ptr->sndr_net, ip);
        asnLogicMacToStringMac(msg_ptr->sndr, mac);
	asLogMessage("asnGenArpMsgStruct: Info - target: ip=[%s], mac=[%s]", ip, mac);

	inet_pton(AF_INET, ip, arpMsg_ptr->ar_tip);
	if (asn_mac_pton(mac, arpMsg_ptr->ar_tha) == -1)
	{
		asLogMessage("asnGenArpMsgStruct: Error on asn_mac_pton() for target");
		return -1;
	}

	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : asnDelBindingInArpCache
// Description  : delete the binding in the kernel ARP cache
//
// Inputs       : askRelayMessage pointer
// Outputs      : 0 if successful, -1 if not

int asnDelBindingInArpCache(askRelayMessage *msg_ptr)
{
        struct nlmsghdr *nlh;
        struct iovec iov;
        struct msghdr msg;
        struct arpreq arpReq;
        arpsec_nlmsg tmp_nlmsg;
        int rtn = 0;

        // Init the stack struct to avoid potential error
        memset(&iov, 0, sizeof(iov));
        memset(&msg, 0, sizeof(msg));
        memset(&arpReq, 0, sizeof(arpReq));
        memset(&tmp_nlmsg, 0, sizeof(tmp_nlmsg));

        // Create the nelink msg
        nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(arpsec_nlmsg)));
        memset(nlh, 0, NLMSG_SPACE(sizeof(arpsec_nlmsg)));
        nlh->nlmsg_len = NLMSG_SPACE(sizeof(arpsec_nlmsg));
        nlh->nlmsg_pid = arpsec_pid;
        nlh->nlmsg_flags = 0;

        // Create the arpreq structure
        rtn = asnGenArpReqStruct(msg_ptr, &arpReq, ARPSEC_NETLINK_OP_DELETE);
        if (rtn == -1)
        {
                asLogMessage("asnDelBindingInArpCache: Error on asnGenArpReqStruct()");
                free(nlh);
                return -1;
        }

        // Fill up the netlink msg
        tmp_nlmsg.arpsec_opcode = ARPSEC_NETLINK_OP_DELETE;
        tmp_nlmsg.arpsec_dev_ptr = msg_ptr->dev_ptr;
        memcpy(&(tmp_nlmsg.arpsec_arp_req), &arpReq, sizeof(arpReq));
        memcpy(NLMSG_DATA(nlh), &tmp_nlmsg, sizeof(tmp_nlmsg));

        // Create the socket msg
        iov.iov_base = (void *)nlh;
        iov.iov_len = nlh->nlmsg_len;
        msg.msg_name = (void *)&arpsec_nl_dest_addr;
        msg.msg_namelen = sizeof(arpsec_nl_dest_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        // Send the msg to the kernel
        rtn = sendmsg(arpsec_sock_fd, &msg, 0);
        if (rtn == -1)
        {
                asLogMessage("asnDelBindingInArpCache: Error on sending netlink binding remove msg to the kernel [%s]",
                                strerror(errno));
                free(nlh);
                return rtn;
        }
        asLogMessage("asnDelBindingInArpCache: Info - send netlink binding remove msg to the kernel");

        free(nlh);
        return rtn;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : asnAddBindingToArpCache
// Description  : add the binding into kernel ARP cache
//
// Inputs       : askRelayMessage pointer
// Outputs      : 0 if successful, -1 if not

int asnAddBindingToArpCache(askRelayMessage *msg_ptr)
{
	struct nlmsghdr *nlh;
	struct iovec iov;
        struct msghdr msg;
	struct arpreq arpReq;
	arpsec_nlmsg tmp_nlmsg;
        int rtn = 0;

        // Init the stack struct to avoid potential error
        memset(&iov, 0, sizeof(iov));
        memset(&msg, 0, sizeof(msg));
	memset(&arpReq, 0, sizeof(arpReq));
	memset(&tmp_nlmsg, 0, sizeof(tmp_nlmsg));

        // Create the nelink msg
        nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(arpsec_nlmsg)));
        memset(nlh, 0, NLMSG_SPACE(sizeof(arpsec_nlmsg)));
        nlh->nlmsg_len = NLMSG_SPACE(sizeof(arpsec_nlmsg));
        nlh->nlmsg_pid = arpsec_pid;
        nlh->nlmsg_flags = 0;

	// Create the arpreq structure
	rtn = asnGenArpReqStruct(msg_ptr, &arpReq, ARPSEC_NETLINK_OP_BIND);
	if (rtn == -1)
	{
		asLogMessage("asnAddBindingToArpCache: Error on asnGenArpReqStruct()");
		free(nlh);
		return -1;
	}

	// Fill up the netlink msg
	tmp_nlmsg.arpsec_opcode = ARPSEC_NETLINK_OP_BIND;
	tmp_nlmsg.arpsec_dev_ptr = msg_ptr->dev_ptr;
	memcpy(&(tmp_nlmsg.arpsec_arp_req), &arpReq, sizeof(arpReq));
	memcpy(NLMSG_DATA(nlh), &tmp_nlmsg, sizeof(tmp_nlmsg));

	// Create the socket msg
        iov.iov_base = (void *)nlh;
        iov.iov_len = nlh->nlmsg_len;
        msg.msg_name = (void *)&arpsec_nl_dest_addr;
        msg.msg_namelen = sizeof(arpsec_nl_dest_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        // Send the msg to the kernel
        rtn = sendmsg(arpsec_sock_fd, &msg, 0);
        if (rtn == -1)
        {
                asLogMessage("asnAddBindingToArpCache: Error on sending netlink bind msg to the kernel [%s]",
                                strerror(errno));
		free(nlh);
                return rtn;
        }
        asLogMessage("asnAddBindingToArpCache: Info - send netlink bind msg to the kernel");

	free(nlh);
	return rtn;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : asnReplyToArpRequest
// Description  : send the reply to this ARP requset
//
// Inputs       : askRelayMessage pointer
// Outputs      : 0 if successful, -1 if not

int asnReplyToArpRequest(askRelayMessage *msg_ptr)
{
        struct nlmsghdr *nlh;
        struct iovec iov;
        struct msghdr msg;
	arpsec_arpmsg arpMsg;
	arpsec_nlmsg tmp_nlmsg;
        int rtn = 0;

        // Init the stack struct to avoid potential error
        memset(&iov, 0, sizeof(iov));
        memset(&msg, 0, sizeof(msg));
	memset(&arpMsg, 0, sizeof(arpMsg));
	memset(&tmp_nlmsg, 0, sizeof(tmp_nlmsg));

        // Create the nelink msg
        nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(arpsec_nlmsg)));
        memset(nlh, 0, NLMSG_SPACE(sizeof(arpsec_nlmsg)));
        nlh->nlmsg_len = NLMSG_SPACE(sizeof(arpsec_nlmsg));
        nlh->nlmsg_pid = arpsec_pid;
        nlh->nlmsg_flags = 0;

        // Create the arpmsg structure
	rtn = asnGenArpMsgStruct(msg_ptr, &arpMsg);
	if (rtn == -1)
	{
		asLogMessage("asnReplyToArpRequest: Error on asnGenArpMsgStruct()");
		free(nlh);
		return -1;
	}

	// Fill up the netlink msg
	tmp_nlmsg.arpsec_opcode = ARPSEC_NETLINK_OP_REPLY;
	tmp_nlmsg.arpsec_dev_ptr = msg_ptr->dev_ptr;
	memcpy(&(tmp_nlmsg.arpsec_arp_msg), &arpMsg, sizeof(arpMsg));
	memcpy(NLMSG_DATA(nlh), &tmp_nlmsg, sizeof(tmp_nlmsg));

        // Create the socket msg
        iov.iov_base = (void *)nlh;
        iov.iov_len = nlh->nlmsg_len;
        msg.msg_name = (void *)&arpsec_nl_dest_addr;
        msg.msg_namelen = sizeof(arpsec_nl_dest_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        // Send the msg to the kernel
        rtn = sendmsg(arpsec_sock_fd, &msg, 0);
        if (rtn == -1)
        {
                asLogMessage("asnReplyToArpRequest: Error on sending netlink reply msg to the kernel [%s]",
                                strerror(errno));
		free(nlh);
                return rtn;
        }
        asLogMessage("asnReplyToArpRequest: Info - sent netlink reply msg to the kernel");

	free(nlh);
        return rtn;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : asnLoigcMacToStringMac
// Description  : Convert the logic MAC address format into normal string MAC address
//
// Inputs       : log_ptr - logic MAC pointer
//		: str_ptr - string MAC pointer
// Outputs      : void
// Note		: The caller is responsible to make sure the buffer is large enough

void asnLogicMacToStringMac(char *log_ptr, char *str_ptr)
{
	// To convert the logic string "f_f_f_f_f_f" into
	// normal MAC string "ff:ff:ff:ff:ff:ff", each 'f'
	// will be translated into unsigned int at first.
	// Then the number will be formated as 2 hex digits.
	// I know this sounds stupid - but K.I.S.S.
	// daveti Aug 13, 2013

	char mac[ARPSEC_NETLINK_STR_MAC_LEN] = {0};
	char log[ARPSEC_MAC_ADDRESS_LEN] = {0};
	unsigned char num[6] = {0};
	int i = 0;
	int j = 0;
	char *ptr;
	char *head;

	// Duplicate the logic string as we will change it
	strncpy(log, log_ptr, ARPSEC_MAC_ADDRESS_LEN);

	// Bypass the "media" prefix
	ptr = log + strlen("media");
	head = ptr;

	// Parse the logic string
	while (*(ptr+i) != '\0')
	{
		if (*(ptr+i) == '_')
		{
			// Translate the digits into int
			*(ptr+i) = '\0';
			num[j] = (unsigned char)strtoul(head, NULL, 16);

			// Update the corresponding stuffs
			i++;
			j++;
			head = ptr + i;
		}
		i++;
	}

	// Translate the last digits into int
	num[j] = (unsigned char)strtoul(head, NULL, 16);

	// Convert the number into 2-bit hex digtis again
	snprintf(mac, ARPSEC_NETLINK_STR_MAC_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
		num[0], num[1], num[2], num[3], num[4], num[5]);

	strncpy(str_ptr, mac, ARPSEC_NETLINK_STR_MAC_LEN);

	// Debug info
	asLogMessage("asnLogicMacToStringMac: log=[%s], str=[%s]",
			log_ptr, str_ptr);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : asnLoigcIpToStringIp
// Description  : Convert the logic IPv4 address format into dot string IPv4 address
//
// Inputs       : log_ptr - logic IPv4 pointer
//              : str_ptr - string IPv4 pointer
// Outputs      : void
// Note         : The caller is responsible to make sure the buffer is large enough

void asnLogicIpToStringIp(char *log_ptr, char *str_ptr)
{
	char ip[ARPSEC_NETLINK_STR_IPV4_LEN] = {0};
	char *ptr;
	int i = 0;

	// Bypass the "net" prefix and replace the '_'
	ptr = log_ptr + strlen("net");
	while (*(ptr+i) != '\0')
	{
		if (*(ptr+i) != '_')
			ip[i] = *(ptr+i);
		else
			ip[i] = '.';
		i++;
	}
	ip[i] = '\0';

	strncpy(str_ptr, ip, ARPSEC_NETLINK_STR_IPV4_LEN);

	// Debug info - should be comment'd later
	asLogMessage("asnLogicIpToStringIp: log=[%s], str=[%s]",
			log_ptr, str_ptr);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : asn_mac_pton
// Description  : Convert the string MAC address into real MAC address
//
// Inputs       : src - string MAC pointer
//              : dst - real MAC pointer
// Outputs      : 0 - success, -1 - failure

int asn_mac_pton(char *src, unsigned char *dst)
{
	int i;
	int rtn;
	unsigned int p[ARPSEC_ETH_ALEN];

	rtn = sscanf(src, "%x:%x:%x:%x:%x:%x",
		&p[0], &p[1], &p[2], &p[3], &p[4], &p[5]);

	if (rtn != ARPSEC_ETH_ALEN)
	{
		asLogMessage("asn_mac_pton: Error on sscanf [%s]", strerror(errno));
		return -1;
	}

	for (i = 0; i < ARPSEC_ETH_ALEN; i++)
		dst[i] = (unsigned char)p[i];

	return 0;
}
