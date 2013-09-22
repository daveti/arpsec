/*
 * tpmd.h
 * Header file for tpmd
 * Sep 15, 2013
 * root@davejingtian.org
 * http://davejingtian.org
 */

#ifndef TPMD_INCLUDE
#define TPMD_INCLUDE

/* tpmd configurations
NOTE: in future, there should be a conf file
instead of hardcode. But now, make it quick!
*/
#define TPMD_PORT		30004	/* tcsd by default is using port 30003 */
#define TPMD_RECV_BUFF_LEN	8192
#define TPMD_MAX_SOCKETS_QUEUED	50

#endif
