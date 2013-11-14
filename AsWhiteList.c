/*
 * AsWhiteList.c
 * Source file for Arpsec White List
 * AsWhiteList is used to load and parse the whitelist.csv into the arpsecd
 * memory space and to provide the corresponidng white list info for the
 * remote machines before attestation.
 * Sep 26, 2013
 * root@davejingtian.org
 * http://davejingtian.org
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "AsWhiteList.h"
#include "AsLog.h"
#include "AsKrnRelay.h"

/* Global definitions */
static whitelist_entry *aswl[ASWL_ENTRY_NUM_MAX];
static int aswlEntryNum;	// this number (if valid) should be the next available empty entry!

/* AsWhiteList methods */

/* Init the white list by allocating the memory and reading the whitelist.csv */
int aswlInitWL(int mode)
{
	int i;

        // Set the mode appropriately
        if ((mode != ASKRN_SIMULATION) && (mode != ASKRN_RELAY))
        {
                asLogMessage("Error on arpsecd mode [%d], aborting", mode);
                return -1;
        }

        // Return success for simulation mode
        if (mode == ASKRN_SIMULATION)
                return 0;

	/* Pre-allocate the memory for the DB */
	for (i = 0; i < ASWL_ENTRY_NUM_MAX; i++)
	{
		aswl[i] = (whitelist_entry *)calloc(1, sizeof(whitelist_entry));
	}
	aswlEntryNum = 0;

	/* Load and parse the tpmdb.csv */
	if (aswlLoadParseCsv(ASWL_WHITE_LIST_FILE_PATH) != 0)
	{
		asLogMessage("Error: white list loading or parsing failure");
		return -1;
	}
	else
		asLogMessage("Info: white list loading and parsing success");

	return 0;
}

/* Free all the memory used by white list */
void aswlShutdownWL(void)
{
	int i;
	
	/* Free the DB */
	for (i = 0; i < ASWL_ENTRY_NUM_MAX; i++)
		free(aswl[i]);
		
	asLogMessage("Info: white list cleared");
}

/* Load and parse the whitelist.csv */
int aswlLoadParseCsv(char *csv)
{
	FILE *f;
	char buf[ASWL_READ_BUF_LEN];
	char *ptr;
	char *head;
	whitelist_entry tmpEntry;

	/* Open the csv file */
	f = fopen(csv, "r");
	if (f == NULL)
	{
		asLogMessage("Error on loading file [%s] [%s]\n", csv, strerror(errno));
		return -1;
	}

	/* Do the damn read */
	while (fgets(buf, ASWL_READ_BUF_LEN, f))
	{
		/* Prepare for reading */
		memset(&tmpEntry, 0, sizeof(tmpEntry));
		ptr = buf;

		/* Filter useless things */
		if (ptr == NULL || *ptr == '\0' || *ptr == '#' || *ptr == '\n')
			continue;

		/* Read through whitespace */
		while (*ptr == ' ' || *ptr == '\t')
			ptr++;

		/* Ignore comments */
		if (*ptr == '#')
			continue;

		/* Ignore the csv header */
		if (*ptr == 'm')
			continue;

		/* Process the entry line here
		 * NOTE: no defensive checking here because daveti is lazy!
		 */

		/* mac */
		head = ptr;
		while (*ptr != ',')
			ptr++;
		*ptr = '\0';
		strcpy(tmpEntry.mac, head);
		ptr++;

		/* ipv4  - last field */
		head = ptr;
		head = ptr;
		while (*ptr != ',' && *ptr != '\n' && *ptr != '\0')
			ptr++;
		*ptr = '\0';
		strcpy(tmpEntry.ipv4, head);

		/* Copy the tmp entry into white list */
		memcpy(aswl[aswlEntryNum], &tmpEntry, sizeof(tmpEntry));

		/* Check if there is no memory for the left entries */
		aswlEntryNum++;
		if (aswlEntryNum == ASWL_ENTRY_NUM_MAX)
		{
			asLogMessage("Warning: no memory for the extra entries in White List - "
					"currently only support [%d] entries; "
					"all the left ones will be ignored.",
					ASWL_ENTRY_NUM_MAX);
			break;
		}
	}

	fclose(f);
	return 0;
}

/* Display and debug */
void aswlDisplayWL(void)
{
	int i;

	for (i = 0; i < aswlEntryNum; i++)
	{
		printf("White List Entry [%d]\n", i);
		aswlDisplayEntry(aswl[i]);
	}
}

/* Display and debug */
void aswlDisplayEntry(whitelist_entry *entry)
{
	printf("MAC = [%s]\n"
		"IPv4 = [%s]\n",
		entry->mac,
		entry->ipv4);
}

/* Find the entry based on MAC */
whitelist_entry *aswlFindEntryBasedOnMac(char *mac)
{
	int i;

	for (i = 0; i < aswlEntryNum; i++)
	{
		if (strcasecmp(mac, aswl[i]->mac) == 0)
			return aswl[i];
	}

	return NULL;
}

/* Find the entry based on IPv4 */
whitelist_entry *aswlFindEntryBasedOnIp(char *ip)
{
	int i;

	for (i = 0; i < aswlEntryNum; i++)
	{
		if (strcasecmp(ip, aswl[i]->ipv4) == 0)
			return aswl[i];
	}

	return NULL;
}

/* Check if the MAC/IP binding is in the white list */
int aswlCheckMacIpTrusted(char *mac, char *ip)
{
	whitelist_entry *entry;

	entry = aswlFindEntryBasedOnMac(mac);
	if (entry != NULL)
		if (strcasecmp(ip, entry->ipv4) == 0)
			return 1;
	return 0;
}

/* Add the MAC/IP binding into the white list - as a cache */
int aswlAddMacIpTrusted(char *mac, char *ip)
{
	/* First need to check if we have the room */
	if (aswlEntryNum >= ASWL_ENTRY_NUM_MAX)
	{
		asLogMessage("Error: Unable to add MAC/IP [%s|%s] into the whitelist - no extra space", mac, ip);
		return -1;
	}

	/* Second to see if the binding is already there */
	if (aswlCheckMacIpTrusted(mac, ip) == 1)
	{
		asLogMessage("Warining: The MAC/IP [%s|%s] is already in the white list", mac, ip);
		return 0;
	}

	/* Now add this new binding */
	whitelist_entry tmpEntry;
	memset(&tmpEntry, 0, sizeof(tmpEntry));
	strcpy(tmpEntry.mac, mac);
	strcpy(tmpEntry.ipv4, ip);
	memcpy(aswl[aswlEntryNum], &tmpEntry, sizeof(tmpEntry));
	aswlEntryNum++;

	return 0;
}


