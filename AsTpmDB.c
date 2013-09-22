/*
 * AsTpmDB.c
 * Source file for Arpsec TPM DB
 * AsTpmDB is used to load and parse the tpmdb.csv into the arpsecd
 * memory space and to provide the corresponidng TPM info for the
 * remote machines during attestation.
 * Sep 18, 2013
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
#include "AsTpmDB.h"
#include "AsLog.h"
#include "AsKrnRelay.h"

/* Global definitions */
static tpmdb_entry *astdb[ASTPMDB_ENTRY_NUM_MAX];
static int astdbEntryNum;

/* Internal methods */
static int convert_pcr_mask(unsigned char *dst, char *pcrMask)
{
	int i;
	char tmp[2];

	/* Defensive checking */
	if (dst == NULL || pcrMask == NULL)
		return -1;

	if (strlen(pcrMask) != ASTPMDB_PCR_MASK_LEN)
	{
		asLogMessage("Error on field 'pcrMask' - less than required length [%d]",
				ASTPMDB_PCR_MASK_LEN);
		return -1;
	}

	/* User's responsibility to make sure the dst is large enough */
	for (i = 0; i < ASTPMDB_PCR_MASK_LEN; i++)
	{
		memset(tmp, 0, 2);
		tmp[0] = pcrMask[i];
		dst[i] = (unsigned char)strtoul(tmp, NULL, 10);
	}

	return 0;
}

static void display_uchar(unsigned char *src, int len, char *header)
{
	int i;
	int new_line;

	printf("%s\n", header);

	for (i = 0; i < len; i++)
	{
		if ((i+1) % ASTPMDB_NUM_PER_LINE != 0)
		{
			printf("%02x ", src[i]);
			new_line = 0;
		}
		else
		{
			printf("%02x\n", src[i]);
			new_line = 1;
		}
	}

	if (new_line == 0)
		printf("\n");
}

/* AsTpmDB methods */

/* Init the TPM DB by allocating the memory and reading the tpmdb.csv */
int astdbInitDB(int mode)
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
	for (i = 0; i < ASTPMDB_ENTRY_NUM_MAX; i++)
	{
		astdb[i] = (tpmdb_entry *)calloc(1, sizeof(tpmdb_entry));
	}
	astdbEntryNum = 0;

	/* Load and parse the tpmdb.csv */
	if (astdbLoadParseCsv(ASTPMDB_TPMDB_FILE_PATH) != 0)
	{
		asLogMessage("Error: TPM DB loading or parsing failure");
		return -1;
	}
	else
		asLogMessage("Info: TPM DB loading and parsing success");

	return 0;
}

/* Free all the memory used by TPM DB */
void astdbShutdownDB(void)
{
	int i;
	
	/* Free the internal memory */
	for (i = 0; i < astdbEntryNum; i++)
		astdbFreeMemForEntry(astdb[i]);

	/* Free the DB */
	for (i = 0; i < ASTPMDB_ENTRY_NUM_MAX; i++)
		free(astdb[i]);
		
	asLogMessage("Info: TPM DB cleared");
}

/* Allocate (internal) memory for DB entry */
void astdbAllocMemForEntry(tpmdb_entry *entry)
{
}

/* Free (internal) memory for DB entry */
void astdbFreeMemForEntry(tpmdb_entry *entry)
{
	if (entry != NULL)
	{
		if (entry->aikPubKeyFilePath != NULL)
                	free(entry->aikPubKeyFilePath);
		if (entry->aikPubKey != NULL)
                	free(entry->aikPubKey);
		if (entry->pcrFilePath != NULL)
                	free(entry->pcrFilePath);
		if (entry->pcrGoodValue != NULL)
                	free(entry->pcrGoodValue);
	}
}

/* Load and parse the tpmdb.csv */
int astdbLoadParseCsv(char *csv)
{
	FILE *f;
	int rtn;
	int badRead = 0;
	char buf[ASTPMDB_READ_BUF_LEN];
	char *ptr;
	char *head;
	tpmdb_entry tmpEntry;
	memset(&tmpEntry, 0, sizeof(tmpEntry));

	/* Open the csv file */
	f = fopen(csv, "r");
	if (f == NULL)
	{
		asLogMessage("Error on loading file [%s] [%s]\n", csv, strerror(errno));
		return -1;
	}

	/* Do the damn read */
	while (fgets(buf, ASTPMDB_READ_BUF_LEN, f))
	{
		/* Prepare for reading */
		if (badRead == 1)
		{
			astdbFreeMemForEntry(&tmpEntry);
			badRead = 0;
		}
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

		/* ipv4 */
		head = ptr;
		while (*ptr != ',')
			ptr++;
		*ptr = '\0';
		strcpy(tmpEntry.ipv4, head);
		ptr++;

		/* aikPubKeyLen */
		head = ptr;
		while (*ptr != ',')
			ptr++;
		*ptr = '\0';
		tmpEntry.aikPubKeyLen = (int)strtoul(head, NULL, 10);
		ptr++;

		/* aikPubKeyFilePath */
		head = ptr;
		while (*ptr != ',')
			ptr++;
		*ptr = '\0';
		tmpEntry.aikPubKeyFilePath = strdup(head);
		ptr++;

		/* pcrMask */
		head = ptr;
		while (*ptr != ',')
			ptr++;
		*ptr = '\0';
		if (convert_pcr_mask(tmpEntry.pcrMask, head) != 0)
		{
			asLogMessage("Error on convert_pcr_mask for field 'pcrMask' [%s], "
					"The whole entry will be ignoreed", head);
			badRead = 1;
			continue;
		}
		ptr++;

		/* pcrLen */
		head = ptr;
		while (*ptr != ',')
			ptr++;
		*ptr = '\0';
		tmpEntry.pcrLen = (int)strtoul(head, NULL, 10);
		ptr++;

		/* pcrFilePath  - last field! */
		head = ptr;
		while (*ptr != ',' && *ptr != '\n' && *ptr != '\0')
			ptr++;
		*ptr = '\0';
		tmpEntry.pcrFilePath = strdup(head);

		/* Read in the key file */
		tmpEntry.aikPubKey = (unsigned char *)calloc(1, tmpEntry.aikPubKeyLen);
		rtn = astdbLoadBinary(tmpEntry.aikPubKey, tmpEntry.aikPubKeyFilePath);
		if (rtn != tmpEntry.aikPubKeyLen)
		{
			asLogMessage("Error on astdbLoadBinary for file [%s] - will ignore the whole entry",
					tmpEntry.aikPubKeyFilePath);
			badRead = 1;
			continue;
		}

		/* Read in the PCR file */
		tmpEntry.pcrGoodValue = (unsigned char *)calloc(1, tmpEntry.pcrLen);
		rtn = astdbLoadBinary(tmpEntry.pcrGoodValue, tmpEntry.pcrFilePath);
		if (rtn != tmpEntry.pcrLen)
		{
			asLogMessage("Error on astdbLoadBinary for file [%s] - will ignore the whole entry",
					tmpEntry.pcrFilePath);
			badRead = 1;
			continue;
		}

		/* Copy the tmp entry into TPM DB */
		memcpy(astdb[astdbEntryNum], &tmpEntry, sizeof(tmpEntry));

		/* Check if there is no memory for the left entries */
		astdbEntryNum++;
		if (astdbEntryNum == ASTPMDB_ENTRY_NUM_MAX)
		{
			asLogMessage("Warning: no memory for the extra entries in TPM DB - "
					"currently only support [%d] entries; "
					"all the left ones will be ignored.",
					ASTPMDB_ENTRY_NUM_MAX);

			/* DO NOT FREE THE INTERNAL MEMORY HERE! */
			break;
		}
	}

	fclose(f);
	return 0;
}

/* Load the binary file (key file or PCR file) */
int astdbLoadBinary(unsigned char *dst, char *file)
{
	/* User's responsibility to make sure enough memory */
        int ret;
	int len;
        FILE *f;
        struct stat sbuf;
        memset(&sbuf, 0, sizeof(sbuf));

        /* Open the key file */
        f = fopen(file,"rb");
        if (f == NULL)
        {
                asLogMessage("Error: Unable to open file [%s] [%s]\n", file, strerror(errno));
		return -1;
        }
        else
                asLogMessage("Info: file [%s] is opened\n", file);

        /* Get the file stat */
        stat(file, &sbuf);
        len = (int)sbuf.st_size;
	asLogMessage("Info: Got file length [%d]\n", len);

        /* Read the key data */
        ret = fread(dst, 1, len, f);
        if (ret != len)
        {
                asLogMessage("Error: Unable to read key file\n");
                fclose(f);
		return -1;
        }

        fclose(f);
	return ret;
}

/* Display and debug */
void astdbDisplayDB(void)
{
	int i;

	for (i = 0; i < astdbEntryNum; i++)
	{
		printf("TPM DB Entry [%d]\n", i);
		astdbDisplayEntry(astdb[i]);
	}
}

/* Display and debug */
void astdbDisplayEntry(tpmdb_entry *entry)
{
	printf("MAC = [%s]\n"
		"IPv4 = [%s]\n"
		"AIK pub key file path = [%s]\n"
		"PCR file path = [%s]\n"
		"AIK pub key len = [%d]\n"
		"PCR len = [%d]\n",
		entry->mac,
		entry->ipv4,
		entry->aikPubKeyFilePath,
		entry->pcrFilePath,
		entry->aikPubKeyLen,
		entry->pcrLen);
	display_uchar(entry->aikPubKey, entry->aikPubKeyLen, "AIK pub key:");
	display_uchar(entry->pcrMask, ASTPMDB_PCR_MASK_LEN, "PCR mask:");
	display_uchar(entry->pcrGoodValue, entry->pcrLen, "PCR good value:");
}

/* Find the entry based on MAC */
tpmdb_entry *astdbFindEntryBasedOnMac(char *mac)
{
	int i;

	for (i = 0; i < astdbEntryNum; i++)
	{
		if (strcasecmp(mac, astdb[i]->mac) == 0)
			return astdb[i];
	}

	return NULL;
}

/* Find the entry based on IPv4 */
tpmdb_entry *astdbFindEntryBasedOnIp(char *ip)
{
	int i;

	for (i = 0; i < astdbEntryNum; i++)
	{
		if (strcasecmp(ip, astdb[i]->ipv4) == 0)
			return astdb[i];
	}

	return NULL;
}
	
