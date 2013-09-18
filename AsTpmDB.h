/*
 * AsTpmDB.h
 * Header file for Arpsec TPM DB
 * Sep 18, 2013
 * root@davejingtian.org
 * http://davejingtian.org
 */

#ifndef AsTpmDB_INCLUDE
#define AsTpmDB_INCLUDE

/* Definitions tpmdb.csv has to follow */
#define ASTPMDB_TPMDB_FILE_PATH		"./tpmdb.csv"
#define ASTPMDB_NUM_PER_LINE		20
#define ASTPMDB_READ_BUF_LEN		1024
#define ASTPMDB_ENTRY_NUM_MAX		10
#define ASTPMDB_MAC_LEN			sizeof("ff:ff:ff:ff:ff:ff")
#define ASTPMDB_IPV4_LEN		sizeof("255.255.255.255")
#define ASTPMDB_PCR_MASK_LEN		24

/* Definition for each entry in tpmdb.csv */
typedef struct _tpmdb_entry
{
	char mac[ASTPMDB_MAC_LEN];
	char ipv4[ASTPMDB_IPV4_LEN];
	int aikPubKeyLen;
	char *aikPubKeyFilePath;
	unsigned char *aikPubKey;
	unsigned char pcrMask[ASTPMDB_PCR_MASK_LEN];
	int pcrLen;
	char *pcrFilePath;
	unsigned char *pcrGoodValue;
} tpmdb_entry;


/* AsTpmDB methods */

/* Init the TPM DB by allocating the memory and reading the tpmdb.csv */
int astdbInitDB(int mode);

/* Free all the memory used by TPM DB */
void astdbShutdownDB(void);

/* Allocate (internal) memory for DB entry */
void astdbAllocMemForEntry(tpmdb_entry *entry);

/* Free (internal) memory for DB entry */
void astdbFreeMemForEntry(tpmdb_entry *entry);

/* Load and parse the tpmdb.csv */
int astdbLoadParseCsv(char *csv);

/* Load the binary file (key file or PCR file) */
int astdbLoadBinary(unsigned char *dst, char *file);

/* Display and debug */
void astdbDisplayEntry(tpmdb_entry *entry);

/* Display and debug */
void astdbDisplayDB(void);

/* Find the entry based on MAC */
tpmdb_entry *astdbFindEntryBasedOnMac(char *mac);

/* Find the entry based on IPv4 */
tpmdb_entry *astdbFindEntryBasedOnIp(char *ip);
	

#endif
