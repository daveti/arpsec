/*
 * AsWhiteList.h
 * Header file for Arpsec White List
 * Sep 26, 2013
 * root@davejingtian.org
 * http://davejingtian.org
 */

#ifndef AsWhiteList_INCLUDE
#define AsWhiteList_INCLUDE

/* Definitions whitelist.csv has to follow */
#define ASWL_WHITE_LIST_FILE_PATH	"./whitelist.csv"
#define ASWL_READ_BUF_LEN		128
#define ASWL_ENTRY_NUM_MAX		10
#define ASWL_MAC_LEN			sizeof("ff:ff:ff:ff:ff:ff")
#define ASWL_IPV4_LEN			sizeof("255.255.255.255")

/* Definition for each entry in whitelist.csv */
typedef struct _whitelist_entry
{
	char mac[ASWL_MAC_LEN];
	char ipv4[ASWL_IPV4_LEN];
} whitelist_entry;


/* AsWhiteList methods */

/* Init the white list (WL) by allocating the memory and reading the whitelist.csv */
int aswlInitWL(int mode);

/* Free all the memory used by WL */
void aswlShutdownWL(void);

/* Load and parse the whitelist.csv */
int aswlLoadParseCsv(char *csv);

/* Display and debug */
void aswlDisplayEntry(whitelist_entry *entry);

/* Display and debug */
void aswlDisplayWL(void);

/* Find the entry based on MAC */
whitelist_entry *aswlFindEntryBasedOnMac(char *mac);

/* Find the entry based on IPv4 */
whitelist_entry *aswlFindEntryBasedOnIp(char *ip);

/* Check if the MAC/IP binding is in the white list */
int aswlCheckMacIpTrusted(char *mac, char *ip);

/* Add the MAC/IP binding into the white list - used as a cache */
int aswlAddMacIpTrusted(char *mac, char *ip);

	
#endif
