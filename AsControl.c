////////////////////////////////////////////////////////////////////////////////
//
//  File          : AsControl.c
//  Description   : The AsControl module implements a shim for the system
//                  trust validation for the arpsec deamon
//
//  Author  : Patrick McDaniel
//  Created : Tue Mar 26 10:25:00 EDT 2013
//  Dev	    : daveti

//
// Includes
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>

// Project Includes
#include "AsControl.h"
#include "AsLogic.h"
#include "AsKrnRelay.h"
#include "AsLog.h"
#include "AsTMeasure.h"
#include "AsNetlink.h"
#include "AsTpmDB.h"
#include "AsWhiteList.h"
#include "tpmw.h"
#include "timer_queue.h"
#include "timer_thread.h"

// Defines
#define SELECT_WAIT_PERIOD 1

// Module data
int	ascControlDone = 0;
int	ascForceAttestFlag = 0;	    // daveti: Force the attestation even if the logic approves
int	ascEnableCacheFlag = 0;	    // daveti: Enable cache (using the whitelist) if the attestation succeeds
int 	ascDisableLogicFindBindingsFlag = 0;	// daveti: disable the aslFindXXXBindings calls for perf debugging
int	ascDisableLogicAddBindingsFlag = 0;	// daveti: dsiable the aslAddBindingsXXX calls for perf debugging
char	*ascLocalSystem = NULL;	    // The name of the local system (logic format)
char	*ascLocalNet = NULL;	    // The local network address name (logic format)
char	*ascLocalMedia = NULL;	    // The local media address name (logic format)
extern pthread_mutex_t	timer_queue_mutex;	// daveti: timer queue mutex
static pthread_t	timer_thread_tid;	// daveti: timer thread id
//
// Module functions

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascDisableLogicAddBindings
// Description  : Disable the aslAddBindingsXXX calls in the ARP msg processing
//
// Inputs       : void
// Outputs      : void

void ascDisableLogicAddBindings(void)
{
        ascDisableLogicAddBindingsFlag = 1;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascDisableLogicFindBindings
// Description  : Disable the aslFindXXXBinding calls in the ARP msg processing
//
// Inputs       : void
// Outputs      : void

void ascDisableLogicFindBindings(void)
{
        ascDisableLogicFindBindingsFlag = 1;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascEnableCache
// Description  : Enable the cache (using the whitelist) if the attestation succeeds
//
// Inputs       : void
// Outputs      : void

void ascEnableCache(void)
{
        ascEnableCacheFlag = 1;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascForceAttest
// Description  : Force the attestation even if the logic approves - for UT!
//
// Inputs       : void
// Outputs      : void

void ascForceAttest(void)
{
	ascForceAttestFlag = 1;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascGetLocalNet
// Description  : Get the local infomation associated with this process
//
// Inputs       : void
// Outputs      : ascLocalNet

char *ascGetLocalNet(void)
{
    return ascLocalNet;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascGetLocalMedia
// Description  : Get the local infomation associated with this process
//
// Inputs       : void
// Outputs      : ascLocalMedia

char *ascGetLocalMedia(void)
{
    return ascLocalMedia;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascSetLocalSystem
// Description  : Setup the local infomation associated with this process
//
// Inputs       : sys - the local system name
// Outputs      : 0 if successful, -1 if not

void ascSetLocalSystem( char *sys ) {
    // Set value and return
    ascLocalSystem = sys;
    return;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascSetLocalNet
// Description  : Setup the local infomation associated with this process
//
// Inputs       : net - the local network address
// Outputs      : 0 if successful, -1 if not

void ascSetLocalNet( char *net) {
    // Set value and return
    ascLocalNet = net;
    return;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascSetLocalMedia
// Description  : Setup the local infomation associated with this process
//
// Inputs       : med - the local media address
// Outputs      : 0 if successful, -1 if not

void ascSetLocalMedia(  char *med ) {
    // Set value and return
    ascLocalMedia = med;
    return;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: ascDumpLocalInfo
// Description	: Dump the local information for debugging
//
// Inputs	: void
// Outputs	: void
// Dev		: daveti

void ascDumpLocalInfo(void)
{
	asLogMessage("Info - LocalSystem: %s", ascLocalSystem);
	asLogMessage("Info - LocalNet: %s", ascLocalNet);
	asLogMessage("Info - LocalMedia: %s", ascLocalMedia);
	return;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascReleaseMemForLocalInfo
// Description  : Release the memory for local information
//
// Note		: This function only works for ASKRN_RELAY mode!
// Inputs       : void
// Outputs      : void
// Dev          : daveti

void ascReleaseMemForLocalInfo(void)
{
	// free the memory for setup local info
	if (ascLocalSystem)
		free(ascLocalSystem);
	if (ascLocalNet)
		free(ascLocalNet);
	if (ascLocalMedia)
		free(ascLocalMedia);

        return;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascPendingNetworkBinding
// Description  : determine whether this response is in relation to prev request
//
// Inputs       : addr - the address to check
// Outputs      : 1 if successful, 0 if failure
// Dev		: daveti

int ascPendingNetworkBinding( AsNetworkAddress addr ) {
    // For now, just return pending for everything
    // asLogMessage( "PENDING NETWORK BINDING: UNIMPLEMNTED, returning TRUE" );
    // daveti: we have no idea if this response is related with our prev request
    // as we do not trace the ARP request from the kernel. However, based on the
    // assumption that all the corresponding response should have the target as
    // arpsecd, we will determine if this response is the one we are waiting for.
    // NOTE: this assumption includes all the responses with the same target....

    // Check if the network address is ourselves
    asLogMessage("ascPendingNetworkBinding: Debug - addr [%s], asLocalNet [%s]",
		addr, ascLocalNet);
    if (strcasecmp(addr, ascLocalNet) == 0)
    	return 1;

    return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascPendingMediaBinding
// Description  : determine whether this response is in relation to prev request
//
// Inputs       : addr - the address to check
// Outputs      : 1 if successful, 0 if failure
// Dev		: daveti

int ascPendingMediaBinding( AsMediaAddress addr )  {
    // For now, just return pending for everything
    // asLogMessage( "PENDING MEDIA BINDING: UNIMPLEMNTED, returning TRUE" );
    // daveti: the same comments above, Man~!
    
    // Check if the MAC address is ourselves
    asLogMessage("ascPendingMediaBinding: Debug - addr [%s], asLocalMedia [%s]",
		addr, ascLocalMedia);
    if (strcasecmp(addr, ascLocalMedia) == 0)
	return 1;

    return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascProcessArpRequest
// Description  : process a received ARP request message
//
// Inputs       : msg - received message
// Outputs      : 0 if successful, -1 if failure
// Dev		: daveti

int ascProcessArpRequest( askRelayMessage *msg ) {

    //Local variables
    int ret = 0;
    AsTime now = time(NULL);
    char media[MAX_MEDADDR_LENGTH];
    AsMediaAddress med = media;

    // Do a quick sanity check
    if ( msg->op != RFC_826_ARP_REQ ) {
	asLogMessage( "ascProcessArpRequest: Insane relay message opcode [%d]", msg->op );
	exit( -1 );
    }

    // If the local interface is the one that we are looking for
    if ( strcmp( msg->target.network, ascLocalNet ) == 0 ) {

	// TODO: implement the arp response tickle of the kernel when we have it
	// asLogMessage( "ascProcessArpRequest: UNIMPLEMNTED ARP RESPONSE, waiting for kernel" );
	// ret = -1;
	// daveti
	ret = asnReplyToArpRequest(msg);
	if (ret == -1)
		asLogMessage("ascProcessArpRequest: Error on asnReplyToArpRequest()");
	else
		asLogMessage("ascProcessArpRequest: Info - ARP reply sent");


    } else {

	// Check to see if we have a good binding for this
	if (ascDisableLogicFindBindingsFlag == 0)
	{
		asStartMetricsTimer();
		if ( aslFindValidMediaBinding( msg->target.network, med, now ) )  {
	    		asLogMessage( "Found good ARP REQ binding [%s->%s]", msg->target.network, med );
		} else {
	    		asLogMessage( "Failed to find good ARP REQ binding [%s]", msg->target.network );
		}
		asStopMetricsTimer( "ARP Binding" );
	} else {
		asLogMessage("ascProcessArpRequest: Info - aslFindValidMediaBinding() is disabled");
	}
    }

    // Return the return code
    return( ret );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascProcessArpResponse
// Description  : process a received ARP response message
//
// Inputs       : msg - received message
// Outputs      : 0 if successful, -1 if failure
// Dev		: daveti

int ascProcessArpResponse( askRelayMessage *msg ) {

    //Local variables
    int ret = 0;
    int bound = 0;
    int trusted = 0;
    AsTime now = time(NULL);
    char mac[ARPSEC_NETLINK_STR_MAC_LEN];
    char ip[ARPSEC_NETLINK_STR_IPV4_LEN];
    timer_queue_msg *tqm;

    // Do a quick sanity check
    if ( msg->op != RFC_826_ARP_RES ) {
	asLogMessage( "ascProcessArpResponse: Insane relay message opcode [%d]", msg->op );
	exit( -1 );
    }

    // Convert the logic MAC/IPv4 to normal string MAC/IPv4
    asnLogicMacToStringMac(msg->sndr, mac);
    asnLogicIpToStringIp(msg->sndr_net, ip);

    // If this was a response we were looking for
    //if ( ascPendingNetworkBinding(msg->target.network) ) {
    // daveti: msg->target.network is saving the sender's IPv4!
    if (ascPendingNetworkBinding(msg->dest_net))
    {
	asLogMessage("ascProcessArpResponse: Info - pending ARP response for arpsecd");

	// daveti: Before running the logic and updating the ARP cache, let's check the
	// black list for MAC at first. If the MAC is in the black list,
	// we do nothing except logging the warning for this malicious MAC.
	// Otherwise, move on as we do usually.
	// daveti: if ascForceAttestFlag is enabled, even though this is the MAC in the
	// black list, we will move on doing attestation to avoid potential DDoS/DoS attack.
	// NOTE: ascForceAttestFlag eventually should work both for black and white list.
	// However, to make it flexible for the hybrid network, we trust white list anyway,
	// as these machines may not have TPM within their machines.
	if (ascForceAttestFlag == 0)
	{
		pthread_mutex_lock(&timer_queue_mutex);
		tqm = tq_get_msg_on_str(TIMER_QUEUE_MSG_TYPE_MAC, mac, TIMER_THREAD_BLACKLIST_MAC);
		pthread_mutex_unlock(&timer_queue_mutex);
		if (tqm != NULL)
		{
			asLogMessage("ascProcessArpResponse: Warning - got ARP response from malicious MAC [%s]",
				mac);
			return -1;
		}
	}

	// daveti: After checking the black list, let's check the White List, to see
	// if the MAC/IP is the one we trust. If it is, the logic layer will be bypassed.
	// This is necessary in the real network env. As we need to trust the DNS and
	// gateway within the network even if they do not have TPMs.
	// NOTE: this is a security hole...ascForceAttestFlag should be considered in future!
	trusted = aswlCheckMacIpTrusted(mac, ip);
	if (trusted)
		asLogMessage("ascProcessArpResponse: Info - found trusted MAC/IPv4 [%s|%s] in the white list",
			mac, ip);

	// Check the source system
	// daveti: add the forceAttestFlag for UT
	// daveti: add the trusted flag for White List
	if ( (!trusted) && ((!aslSystemTrusted(msg->source, now)) || (ascForceAttestFlag == 1)) )  {

	    // daveti: we are not sure if the binding is in the ARP cache or not.
	    // For the case here, it is much more possible that the binding is
	    // removed by the kernel because of timer expiration.

	    // daveti: Before attesting, the binding needs to be
	    // added into ARP cache temperarily.
            ret = asnAddBindingToArpCache(msg);
            if (ret == -1)
                asLogMessage("ascProcessArpResponse: Error on asnAddBindingToArpCache() for temp");
            else {
                asLogMessage("ascProcessArpResponse: Info - ARP cache updated for temp");
		bound = 1;
	    }

	    // Go attest the system
	    //if( astAttestSystem(msg->source) ) {
	    if (astAttestSystem(msg))
	    {
		asLogMessage( "Unable to attest system [%s] at time [%lu], ignoring ARP RES", 
			msg->source, now );

		// daveti: once the attestation fails, the binding needs
		// to be removed from the ARP cache.
        	ret = asnDelBindingInArpCache(msg);
        	if (ret == -1)
                	asLogMessage("ascProcessArpResponse: Error on asnDelBindingInArpCache()");
        	else
                	asLogMessage("ascProcessArpResponse: Info - ARP cache updated (entry removed)");

                // daveti: Add this MAC into the black list to prevent
                // future ARP spoofing and to reduce the overhead of talking
                // with the kernel.
		if (ascForceAttestFlag == 0)
		{
			pthread_mutex_lock(&timer_queue_mutex);
			ret = tq_create_add_msg(TIMER_QUEUE_MSG_TYPE_MAC, mac, TIMER_THREAD_BLACKLIST_MAC);
			pthread_mutex_unlock(&timer_queue_mutex);
			if (ret != 0)
				asLogMessage("ascProcessArpResponse: Error on tq_create_add_msg for MAC [%s]",
					mac);
			asLogMessage("ascProcessArpResponse: Info - add MAC [%s] into the MAC Black List", mac);
		}

		return( -1 );
	    }

	    // Add the attestation time to the logic
	    aslAddTrustStatement( msg->source, now );

	    // Add the MAC/IP into the whitelist (cache) if the attestation succeeds
	    // Currently only ARP response has caching functionality
	    //  - RARP response is not implemented yet!
	    if (ascEnableCacheFlag == 1)
	    {
		asLogMessage("ascProcessArpResponse: Info - add MAC/IP [%s|%s] into the white list", mac, ip);
		if (aswlAddMacIpTrusted(mac, ip) == -1)
			asLogMessage("ascProcessArpResponse: Error on aswlAddMacIpTrusted()");
	    }
	}

	// Ok, now trusted, add binding statement
	if (ascDisableLogicAddBindingsFlag == 0)
	{
		asStartMetricsTimer();
		aslAddBindingStatement( msg->source, msg->binding.media, msg->target.network, now );
		asStopMetricsTimer( "ARP add binding ");
	} else {
		asLogMessage("ascProcessArpResponse: Info - aslAddBindingStatement() is disabled");
	}
	asLogMessage( "Successfully processed ARP RES [%s->%s]", msg->target.network, msg->binding.media);

	// daveti: add the binding into ARP cache
	if (bound == 1)
		asLogMessage("ascProcessArpResponse: Info - ARP cache updated");
	else
	{
		ret = asnAddBindingToArpCache(msg);
		if (ret == -1)
			asLogMessage("ascProcessArpResponse: Error on asnAddBindingToArpCache()");
		else
			asLogMessage("ascProcessArpResponse: Info - ARP cache updated");
	}

    } else {

	asLogMessage("ascProcessArpResponse: Info - non-pending ARP response for arpsecd");

	// daveti: Check the black list to see if we have the MAC already.
	// If so, no logic running or ARP cache update will happen. Otherwise,
	// run into the logic verification.
	if (ascForceAttestFlag == 0)
	{
        	pthread_mutex_lock(&timer_queue_mutex);
        	tqm = tq_get_msg_on_str(TIMER_QUEUE_MSG_TYPE_MAC, mac, TIMER_THREAD_BLACKLIST_MAC);
        	pthread_mutex_unlock(&timer_queue_mutex);
        	if (tqm != NULL)
        	{
                	asLogMessage("ascProcessArpResponse: Warning - got ARP response from malicious MAC [%s]",
                                mac);
                	return -1;
		}
        }

        // daveti: After checking the black list, let's check the White List, to see
        // if the MAC/IP is the one we trust. If it is, the logic layer will be bypassed.
        // This is necessary in the real network env. As we need to trust the DNS and
        // gateway within the network even if they do not have TPMs.
        // NOTE: this is a security hole...
        trusted = aswlCheckMacIpTrusted(mac, ip);
        if (trusted)
                asLogMessage("ascProcessArpResponse: Info - found trusted MAC/IPv4 [%s|%s] in the white list",
                        mac, ip);

	// Check the source system
	// daveti: add the trusted flag for the white list
	if ( (trusted) || (aslSystemTrusted(msg->source, now)) )  {

	    // daveti: As we will not use white list here, we assume the
	    // nice remote machine would not generate the ARP response
	    // storm given the short time...
	
	    // Ok, now trusted, add binding statement
	    if (ascDisableLogicAddBindingsFlag == 0)
	    	aslAddBindingStatement( msg->source, msg->binding.media, msg->target.network, now );
	    else
		asLogMessage("ascProcessArpResponse: Info - aslAddBindingStatement() is disabled");
	    asLogMessage( "Successfully processed foriegn ARP RES [%s->%s]", 
		    msg->target.network, msg->binding.media);

	    // daveti: add the binding into ARP cache
            ret = asnAddBindingToArpCache(msg);
            if (ret == -1)
		asLogMessage("ascProcessArpResponse: Error on asnAddBindingToArpCache()");
	    else
            	asLogMessage("ascProcessArpResponse: Info - ARP cache updated");

	} else {

	    // Foreign IP from untrusted system
	    asLogMessage( "ascProcessArpResponse: ignoring ARP RES for foreign IP [%s]", 
		    msg->target.network );

	    // daveti: Could think about adding the MAC into the black list. However,
	    // current black list only works for the ones failed attestation. As there
	    // is no attestation here, we have no idea if this MAC is really bad or not.
	    // We could add the MAC into the black list, which improves the ARP security
	    // to certain extent...But now, let's leave it as it is:)
	}
    }

    // Otherwise this is intended for somebody else
    return( ret );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascProcessRArpRequest
// Description  : process a received RARP request message
//
// Inputs       : msg - received message
// Outputs      : 0 if successful, -1 if failure
// Dev		: daveti

int ascProcessRArpRequest( askRelayMessage *msg ) {

    //Local variables
    int ret = 0;
    AsTime now = time(NULL);
    char network[MAX_NETADDR_LENGTH];
    AsNetworkAddress net = network;

    // Do a quick sanity check
    if ( msg->op != RFC_903_ARP_RREQ ) {
	asLogMessage( "ascProcessRArpRequest: Insane relay message opcode [%d]", msg->op );
	exit( -1 );
    }

    // If the local interface is the one that we are looking for
    if ( strcmp( msg->target.media, ascLocalMedia ) == 0 ) {

	// TODO: implement the arp response tickle of the kernel when we have it
	// asLogMessage( "ascProcessRArpRequest: UNIMPLEMNTED RARP RESPONSE, waiting for kernel" );
	// ret = -1;
        ret = asnReplyToArpRequest(msg);
        if (ret == -1)
                asLogMessage("ascProcessRArpRequest: Error on asnReplyToArpRequest()");
        else
                asLogMessage("ascProcessRArpRequest: Info - ARP reply sent");

    } else {

	// Check to see if we have a good binding for this
	if (ascDisableLogicFindBindingsFlag == 0)
	{
		asStartMetricsTimer();
		if ( aslFindValidNetworkBinding( net, msg->target.media, now ) )  {
	    		asLogMessage( "Found good ARP binding {%s->%s]", msg->target.media, net );
		} else {
	    		asLogMessage( "Failed to find good RARP REQ binding [%s]", msg->target.media );
		}
		asStopMetricsTimer( "RARP Binding" );
	} else {
		asLogMessage("ascProcessRArpRequest: Info - aslFindValidNetworkBinding() is disabled");
	}
    }

    // Return the processing code
    return( ret );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascProcessRArpResponse
// Description  : process a received RARP response message
//
// Inputs       : msg - received message
// Outputs      : 0 if successful, -1 if failure
// Dev		: daveti

int ascProcessRArpResponse( askRelayMessage *msg ) {

    //Local variables
    int ret = 0;
    int bound = 0;
    int trusted = 0;
    AsTime now = time(NULL);
    char mac[ARPSEC_NETLINK_STR_MAC_LEN];
    char ip[ARPSEC_NETLINK_STR_IPV4_LEN];
    timer_queue_msg *tqm;

    // Do a quick sanity check
    if ( msg->op != RFC_903_ARP_RRES ) {
	asLogMessage( "ascProcessRArpResponse: Insane relay message opcode [%d]", msg->op );
	exit( -1 );
    }

    // Convert the logic MAC/IPv4 to normal string MAC/IPv4
    asnLogicMacToStringMac(msg->sndr, mac);
    asnLogicIpToStringIp(msg->sndr_net, ip);

    // If this was a response we were looking for
    //if ( ascPendingMediaBinding(msg->target.media) ) {
    if (ascPendingMediaBinding(msg->dest))
    {
	asLogMessage("ascProcessRArpResponse: Info - pending RARP response for arpsecd");

        // daveti: Before running the logic and updating the ARP cache, let's check the
        // black list for MAC at first. If the MAC is in the black list,
        // we do nothing except logging the warning for this malicious MAC.
        // Otherwise, move on as we do usually.
	if (ascForceAttestFlag == 0)
	{
        	pthread_mutex_lock(&timer_queue_mutex);
        	tqm = tq_get_msg_on_str(TIMER_QUEUE_MSG_TYPE_IPV4, ip, TIMER_THREAD_BLACKLIST_IPV4);
        	pthread_mutex_unlock(&timer_queue_mutex);
        	if (tqm != NULL)
        	{
                	asLogMessage("ascProcessRArpResponse: Warning - got ARP response from malicious IP [%s]",
                                ip);
                	return -1;
		}
        }

        // daveti: After checking the black list, let's check the White List, to see
        // if the MAC/IP is the one we trust. If it is, the logic layer will be bypassed.
        // This is necessary in the real network env. As we need to trust the DNS and
        // gateway within the network even if they do not have TPMs.
        // NOTE: this is a security hole...
        trusted = aswlCheckMacIpTrusted(mac, ip);
        if (trusted)
                asLogMessage("ascProcessRArpResponse: Info - found trusted MAC/IPv4 [%s|%s] in the white list",
                        mac, ip);

	// Check the source system
	// daveti: add the forceAttestFlag for UT
	if ( (!trusted) && ((!aslSystemTrusted(msg->source, now)) || (ascForceAttestFlag == 1)) )  {

            // daveti: Before attesting, the binding needs to be
            // added into ARP cache temperarily.
            ret = asnAddBindingToArpCache(msg);
            if (ret == -1)
                asLogMessage("ascProcessRArpResponse: Error on asnAddBindingToArpCache() for temp");
            else {
                asLogMessage("ascProcessRArpResponse: Info - ARP cache updated for temp");
		bound = 1;
	    }

	    // Go attest the system
	    //if( astAttestSystem(msg->source) ) {
	    if (astAttestSystem(msg))
	    {
		asLogMessage( "Unable to attest system [%s] at time [%lu], ignoring ARP RES", 
			msg->source, now );

                // daveti: once the attestation fails, the binding needs
                // to be removed from the ARP cache.
                ret = asnDelBindingInArpCache(msg);
                if (ret == -1)
                        asLogMessage("ascProcessRArpResponse: Error on asnDelBindingInArpCache()");
                else
                        asLogMessage("ascProcessRArpResponse: Info - ARP cache updated (entry removed)");

		// daveti: add the malicious IP into the black list to
		// prevent further spoofing and the overhead talking with kernel.
		if (ascForceAttestFlag == 0)
		{
                	pthread_mutex_lock(&timer_queue_mutex);
                	ret = tq_create_add_msg(TIMER_QUEUE_MSG_TYPE_IPV4, ip, TIMER_THREAD_BLACKLIST_IPV4);
                	pthread_mutex_unlock(&timer_queue_mutex);
                	if (ret != 0)
                        	asLogMessage("ascProcessRArpResponse: Error on tq_create_add_msg for IP [%s]",
                                        ip);
			asLogMessage("ascProcessRArpResponse: Info - add the IP [%s] into the IP Black List", ip);
		}

		return( -1 );
	    }

	    // Add the attestation time to the logic
	    aslAddTrustStatement( msg->source, now );
	}

	// Now add the binding statement
	if (ascDisableLogicAddBindingsFlag == 0)
	{
		asStartMetricsTimer();
		aslAddBindingStatement( msg->source, msg->target.media, msg->binding.network, now );
		asStopMetricsTimer( "RARP add binding ");
	} else {
		asLogMessage("ascProcessRArpResponse: Info - aslAddBindingStatement() is disabled");
	}
	asLogMessage( "Successfully processed RARP RES [%s->%s]", msg->target.media, msg->binding.network);

        // daveti: add the binding into ARP cache
	if (bound == 1)
		asLogMessage("ascProcessRArpResponse: Info - ARP cache updated");
	else
	{
        	ret = asnAddBindingToArpCache(msg);
        	if (ret == -1)
                	asLogMessage("ascProcessRArpResponse: Error on asnAddBindingToArpCache()");
        	else
                	asLogMessage("ascProcessRArpResponse: Info - ARP cache updated");
	}

    } else {

	asLogMessage("ascProcessRArpResponse: Info - non-pending RARP response for arpsecd");

        // daveti: Check the black list to see if we have the MAC already.
        // If so, no logic running or ARP cache update will happen. Otherwise,
        // run into the logic verification.
	if (ascForceAttestFlag == 0)
	{
        	pthread_mutex_lock(&timer_queue_mutex);
        	tqm = tq_get_msg_on_str(TIMER_QUEUE_MSG_TYPE_IPV4, ip, TIMER_THREAD_BLACKLIST_IPV4);
        	pthread_mutex_unlock(&timer_queue_mutex);
        	if (tqm != NULL)
        	{
			asLogMessage("ascProcessRArpResponse: Warning - got ARP response from malicious IP [%s]",
                                ip);
                	return -1;
		}
        }

        // daveti: After checking the black list, let's check the White List, to see
        // if the MAC/IP is the one we trust. If it is, the logic layer will be bypassed.
        // This is necessary in the real network env. As we need to trust the DNS and
        // gateway within the network even if they do not have TPMs.
        // NOTE: this is a security hole...
        trusted = aswlCheckMacIpTrusted(mac, ip);
        if (trusted)
                asLogMessage("ascProcessRArpResponse: Info - found trusted MAC/IPv4 [%s|%s] in the white list",
                        mac, ip);

	// Check the source system
	if ( (trusted) || (aslSystemTrusted(msg->source, now)) )  {

	    // Now add the binding statement
	    if (ascDisableLogicAddBindingsFlag == 0)
	    	aslAddBindingStatement( msg->source, msg->target.media, msg->binding.network, now );
	    else
		asLogMessage("ascProcessRArpResponse: Info - aslAddBindingStatement() is disabled");
	    asLogMessage( "Successfully processed foreign RARP RES [%s->%s]", 
		    msg->target.media, msg->binding.network);

            // daveti: add the binding into ARP cache
	    ret = asnAddBindingToArpCache(msg);
            if (ret == -1)
                    asLogMessage("ascProcessRArpResponse: Error on asnAddBindingToArpCache()");
            else
                    asLogMessage("ascProcessRArpResponse: Info - ARP cache updated");


	} else {

	    // Ignore message
	    asLogMessage( "ascProcessRArpResponse: ignoring RARP RES for foreign IP [%s]", 
		    msg->target.network );
	}
    }

    // Otherwise this is intended for somebody else
    return( ret );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascProcessMessage
// Description  : process a received ARP message
//
// Inputs       : msg - received message
// Outputs      : pointer to the message or NULL if failure

int ascProcessMessage( askRelayMessage *msg ) {

    // Log the fact that we got the message
    int ret;
    char buf[256];
// daveti: add timing
struct timeval tpstart,tpend;
float timeuse = 0;

    asLogMessage( "Processing ARP from kernel [%s]", askMessageToString(msg,buf, 256) );


    // If we are the soruce, just ignore
    if ( strcmp(msg->sndr, ascLocalMedia) == 0 ) {
	asLogMessage( "Ignoring message sent mby local stack [%s]", askMessageToString(msg,buf, 256) );
	return( 0 );
    }

    // Figure out which message we are sending
    switch (msg->op) {
    
	case RFC_826_ARP_REQ:    // ARP Request
	ret = ascProcessArpRequest( msg );
	break;

	case RFC_826_ARP_RES:    // ARP Response
//daveti: timing for ARP response processing
{
gettimeofday(&tpstart,NULL);

	ret = ascProcessArpResponse( msg );

//daveti: end timing
gettimeofday(&tpend,NULL);
timeuse=1000000*(tpend.tv_sec-tpstart.tv_sec)+tpend.tv_usec-tpstart.tv_usec;
timeuse/=1000000;
asLogMessage("arpsec - Total time on ascProcessArpResponse_time() is [%f] ms", timeuse);
}

	break;

	case RFC_903_ARP_RREQ:   // ARP Reverse Request
	ret = ascProcessRArpRequest( msg );
	break;

	case RFC_903_ARP_RRES:   // ARP Reverse Response
	ret = ascProcessRArpResponse( msg );
	break;

	default:
	asLogMessage( "Unknown ARP packet, aborting [%d]", msg->op );
	exit( -1 );
    }

    // Return the return code
    return( ret );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascControlLoop
// Description  : This is the control loop used for the arpsec deamon
//
// Inputs       : mode - simulate or run normally
// Outputs      : 0 if successful, -1 if no

int ascControlLoop( int mode ) {
    
    // Local variables
    //int rval, nfds, sim, fh;
    int rval, nfds, sim;
    struct timeval next;
    struct timeval tpstart, tpend;
    float timeuse;
    fd_set rdfds, wrfds;
    askRelayMessage *msg;
#ifdef UNIT_TESTING
    int rnd;
#endif

    // Setup the signal handler 
    signal( SIGINT, ascSigIntHandler );
    signal( SIGHUP, ascSigHupHandler );

    // Intalialize all of the subsystems
    // NOTE: the order of init of subsystems
    // does matters!
    // Sep 21, 2013
    // daveti
    sim = (mode) ? ASKRN_SIMULATION : ASKRN_RELAY;
    if ( aslInitLogic()
	|| (askInitRelay(sim))
	|| (asnInitNetlink(sim))
	|| (astdbInitDB(sim))
	|| (aswlInitWL(sim))
	|| (astInitAttest(sim))
	|| (tq_init_queue_all(sim)) )
    {
	// Log and error out of processing
	asLogMessage( "arpsec daemon initalization failed, aborting.\n" );
	return( -1 );
    }

   // daveti: test the bidirectional netlink socket
   // daveti: test the TPM DB
   // daveti: test the White List
   // daveti: test timer queue and create timer thread
   if (sim == ASKRN_RELAY)
   {
	asnTestNetlink();
	astdbDisplayDB();
	aswlDisplayWL();
	tq_display_queue_all();

	// Create timer thread to control the black lists
	rval = pthread_create(&timer_thread_tid, NULL, timer_thread_main, NULL);
	if (rval != 0)
	{
		asLogMessage("arpsec daemon unable to create timer thread [%s]. Aborting",
				strerror(errno));
		return -1;
	}
	asLogMessage("arpsec daemon timer thread is created");
   }

   // daveti: setup the select before the loop
   nfds = 0;
   FD_ZERO( &rdfds );
   FD_ZERO( &wrfds );
   next.tv_sec = SELECT_WAIT_PERIOD;
   next.tv_usec = 0;
   int *relayfds = askGetRelayHandle3();
   int maxfd = 0;
   int i;
   if (relayfds) {
	for (i = 0; i < ARPSEC_MAX_NUM_OF_CPUS; i++) {
	    if (relayfds[i] != 0) {
		// add this fd into select read set
		FD_SET(relayfds[i], &rdfds);
		asLogMessage("Got file handler[%d]", relayfds[i]);
		
		// Check for max
		if (relayfds[i] > maxfd) {
			maxfd = relayfds[i];
		}
	    } else {
		// No new files
		nfds = maxfd + 1;
		break;
	    }
	}
    }

    // Loop until done
    ascControlDone = 0;
    while ( !ascControlDone ) {

/* daveti - move this outside the loop
	// Setup the select wait
	nfds = 0;
	FD_ZERO( &rdfds );
	FD_ZERO( &wrfds );

	// Set the wait period
	next.tv_sec = SELECT_WAIT_PERIOD;
	next.tv_usec =  0 ; 

	// If the relay has a file handle, use it
	if ( (fh=askGetRelayHandle()) != -1 ) {
	    FD_SET( fh, &wrfds );
	    printf( "Got file handle\n" );
	    nfds = fh+1;
	}
*/
							
	// Do the select, then process the result
	rval = select(nfds, &rdfds, &wrfds, NULL, &next); 
	// asLogMessage( "Out of select ..." );
	if ( rval < 0 ) {

	    // We got an error on the select, prepare to bail out
	    asLogMessage( "Error on control loop select, aborting [%s]", strerror(errno) );
	    ascControlDone = 1;
	} 
	
	else if (rval > 0) {

	    // We select the file handle and should process data
	    printf("daveti: ready to read from relay\n");
	} 

	// Ok, do normal processing
	//if ( (msg = askGetNextMessage()) != NULL ) {
	// daveti: make it a while loop
	while ((msg = askGetNextMessage()) != NULL) {
//daveti: timing
timeuse = 0;
gettimeofday(&tpstart,NULL);

	    ascProcessMessage(msg);

//daveti: timing end
gettimeofday(&tpend,NULL);
timeuse=1000000*(tpend.tv_sec-tpstart.tv_sec)+tpend.tv_usec-tpstart.tv_usec;
timeuse/=1000000;
asLogMessage("arpsec - Total time on ascProcessMessage() is [%f] ms", timeuse);

	    askReleaseBuffer(msg);
	}

#ifdef UNIT_TESTINAG
	// If unit testing simulating
	if ( mode ) {
	    rnd = as_random(10);
	    if ( rnd > 5 ) {
		testAsLogicInterfaces();
	    }
	}
#endif

    }

    // Close downt the procesing
    aslShutdownLogic();
    if (sim == ASKRN_RELAY)
    {
	pthread_kill(timer_thread_tid, SIGTERM);
	askShutdownRelay();
	asnShutdownNetlink();
	astdbShutdownDB();
	aswlShutdownWL();
	tpmw_close_tpm();
	tq_destroy_queue_all();
    }

    // Return sucessfully
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: ascSigIntHandler
// Description	: process the signal for interrupt
//
// Inputs	: the signal (should be SIGINT)
// Outputs	: none

void ascSigIntHandler( int sig ) {
    ascControlDone = 1;
    asLogMessage( "System received SIGINT signal, processing." );
    return;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: ascSigHupHandler
// Description	: process the signal for reset (SIGHUP)
//
// Inputs	: the signal (should be SIGHUP)
// Outputs	: none

void ascSigHupHandler( int sig ) {
    asLogMessage( "System received SIGHUP signal, processing." );
    return;
}

