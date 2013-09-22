/*
 * Header file for protocol AT
 * Detailed design of AT please refer to the web
 * Sep 14, 2013
 * root@davejingtian.org
 * http://davejingtian.org
 */

#ifndef AT_INCLUDE
#define AT_INCLUDE

/* AT macros */
#define AT_MSG_REQ		0
#define AT_MSG_REP		1
#define AT_HEADER_LEN		3
#define AT_PCR_LIST_LEN		24
#define AT_NONCE_LEN		20
#define AT_DATA_LEN		48	// AT_DATA_LEN = AT_DATA_HEADER_LEN + AT_PCR_DIGEST_LEN + AT_NONCE_LEN;
#define AT_SIG_LEN		256
#define AT_PCR_DIGEST_LEN	20
#define AT_DATA_HEADER_LEN	8
#define AT_UCHAR_NUM_PER_LINE	20

/* Definition for AT request/reply */
typedef struct _at_req
{
	char header[AT_HEADER_LEN];	/* { 'a', 't', 'q' } */
	unsigned char pcr_list[AT_PCR_LIST_LEN];
	unsigned char nonce[AT_NONCE_LEN];
} at_req;

typedef struct _at_rep
{
	char header[AT_HEADER_LEN];	/* { 'a', 't', 'p' } */
	unsigned char data[AT_DATA_LEN];
	unsigned char sig[AT_SIG_LEN];
} at_rep;

typedef struct _at_data
{
	unsigned char header[AT_DATA_HEADER_LEN];
	unsigned char digest[AT_PCR_DIGEST_LEN];
	unsigned char nonce[AT_NONCE_LEN];
} at_data;

#define AT_REQ_LEN		sizeof(at_req)
#define AT_REP_LEN		sizeof(at_rep)
#define AT_QUEUE_MSG_NUM	100
#define AT_QUEUE_REQ_SIZE	(AT_REQ_LEN*AT_QUEUE_MSG_NUM)
#define AT_QUEUE_REP_SIZE	(AT_REP_LEN*AT_QUEUE_MSG_NUM)

/* AT protocol related methods */

/* Check if this msg is a valid AT request */
int at_is_msg_req(void *msg);

/* Check if this msg is a valid  AT reply */
int at_is_msg_rep(void *msg);

/* Display the AT request */
void at_display_msg_req(at_req *req);

/* Display the AT reply */
void at_display_msg_rep(at_rep *rep);

/* Display the uchar given length */
void at_display_uchar(unsigned char *src, int len, char *header);

/* Display the PCR list */
void at_display_pcr_list(unsigned char *pcr);


/* AT queue related methods */

/* Init the AT queue */
void at_init_queue(int type);

/* Add msgs into the AT queue */
void at_add_msg_queue(void *msg, int len, int type);

/* Pop the first msg in the queue */
int at_pop_head_msg_queue(void *msg, int type);

/* Get the number of msgs in the queue */
int at_get_msg_num_queue(int type);

/* Clear all the msgs in the queue */
void at_clear_all_msg_queue(int type);

#endif
