#ifndef AsNetlink_INCLUDED
#define AsNetlink_INCLUDED

////////////////////////////////////////////////////////////////////////////////
//
//  File          : AsNetlink.h
//  Description   : The AsNetlink module implements the interface communicating
//			with the Linux kernel using netlink
//
//  Author  : Dave Tian
//  Created : Thu Aug 9 2013
//

// Project Includes
#include "AsKrnRelay.h"
#include <net/if_arp.h>

#define ARPSEC_NETLINK			31
#define ARPSEC_NETLINK_MAX_PAYLOAD	1024
#define ARPSEC_NETLINK_DEV_NAME_LEN     16
#define ARPSEC_NETLINK_OP_TEST          0
#define ARPSEC_NETLINK_OP_REPLY         1
#define ARPSEC_NETLINK_OP_BIND          2
#define ARPSEC_NETLINK_OP_DELETE	3
#define ARPSEC_NETLINK_STR_MAC_LEN	sizeof("ff:ff:ff:ff:ff:ff")
#define ARPSEC_NETLINK_STR_IPV4_LEN	sizeof("255.255.255.255")

typedef struct _arpsec_nlmsg {
        unsigned char           arpsec_opcode;          /* operation code */
        void			*arpsec_dev_ptr;        /* net device ptr */
        union {
                arpsec_arpmsg   arpsec_arp_msg;         /* ARP message */
                struct arpreq   arpsec_arp_req;         /* ioctl ARP message */
        };   
} arpsec_nlmsg;

//
// Module methods
	
// Init the netlink (mode is sym vs. kernel)
int asnInitNetlink(int mode);

// Close the netlink
int asnShutdownNetlink(void);

// Test the bidirection netlink (only for UT!)
void asnTestNetlink(void);

// Insert the ARP binding into the kernel ARP cache
int asnAddBindingToArpCache(askRelayMessage *msg_ptr);

// Delete the ARP binding in the kernel ARP cache
int asnDelBindingInArpCache(askRelayMessage *msg_ptr);

// Trigger the kernel to reply this ARP request
int asnReplyToArpRequest(askRelayMessage *msg_ptr);

// Generate an arpreq struct based on askRelayMessage
int asnGenArpReqStruct(askRelayMessage *msg_ptr, struct arpreq *arpReq_ptr, int opcode);

// Generate an arpmsg struct based on askRelayMessage
int asnGenArpMsgStruct(askRelayMessage *msg_ptr, arpsec_arpmsg *arpMsg_ptr);

// Convert the logic media address ("mediaff_ff...") into string MAC address ("ff:ff...")
void asnLogicMacToStringMac(char *log_ptr, char *str_ptr);

// Convert the logic IPv4 address ("net255_255...") into dot string IPv4 address ("255.255...")
void asnLogicIpToStringIp(char *log_ptr, char *str_ptr);

// Convert the string MAC address into real one
int asn_mac_pton(char *src, unsigned char *dst);
	
#endif
