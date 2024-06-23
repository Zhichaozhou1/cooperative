#ifndef LAB_H
#define LAB_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>
#include <time.h>
#define MAXSIGLEN 1024
#define TABLE_SIZE 1000
#define hex_cnt_sha256 64
#define hmac_resultlen 32
#define True 1
#define False 0
#define rsu_key_initial "1d5c6ed404b9a1f19e6830a098cd481f08a8f6355993a5e89a1067808d058a86"
void* recv_message (void *sock);
void* send_message (void *sock);
void* process();
int init_socket(char* IP_des,int Port_src,int Port_des,char* message,char* pubkey_addr, char* prikey_addr);
int PCGen(unsigned char* prikey_addr, unsigned char* pubkey_addr);
int KeyGen(EC_KEY *ec_key, char* prikey_addr);
int base64_encode(char in_str[], int in_len, char out_str[]);
int base64_decode(char in_str[], int in_len, char out_str[]);
int Sign(EC_KEY *ec_key, unsigned char *sig, const unsigned char digest[], int digest_len);
int SignMain(EC_KEY *ec_key, unsigned char message[], unsigned char *signature, int *sig_len);
int EVP(unsigned char message[],unsigned char digest[], unsigned int *digest_len);
double message_sign(unsigned char beacon[], unsigned char base64message[], unsigned char tesla_key_use[], int flag, unsigned char* prikey_addr, unsigned char* pubkey_addr);
struct valid_PC{
        struct valid_PC* next;
        char* KeyID;
        char* ts;
        char* te;
        char* pubkey;
	char* message_cache;
        char* message_cache_mac;
};

struct HashTable_PC{
        struct valid_PC** table;
};

typedef struct Link{
    char* str;
    struct Link *next;
} queue;

queue * initLink();
queue * insertElem(queue * p,char* msg);
static unsigned int hash_33(char* key);
struct HashTable_PC* hash_table_new();
int hash_table_input(struct HashTable_PC* ht, unsigned char* key, unsigned char* ts, unsigned char* te, unsigned char* pubkey, unsigned char* message_cache, unsigned char* message_cache_mac);
//int hash_table_input(struct HashTable_PC* ht, unsigned char* key, unsigned char* ts, unsigned char* te, unsigned char* pubkey);
int hash_table_get(struct HashTable_PC* ht, char* key, char* pubkey);
int hash_table_get_message(struct HashTable_PC* ht, char* key, char* message_cache, char* message_cache_mac);
int decryption(unsigned char* base64_receive, struct HashTable_PC* Pcert);
int verify(EC_KEY *ec_key, const unsigned char *sig, int siglen, unsigned char message[]);
int message_process(unsigned char base64_receive[], struct HashTable_PC* ht, struct HashTable_PC* ht2, struct HashTable_PC* ht3, int num, queue *queue2_msg_rear, queue *queue3_msg_header);
int key_init(unsigned char *key_origin, int len);
int generate_key_chain(const unsigned char* key, int n, unsigned char* key_chain[]);
unsigned char *HMAC_sha256(const void *key, int keylen, const unsigned char *data, int datalen, unsigned char *result, unsigned int *resultlen);
int verify_HMAC(const void *key, int keylen, const unsigned char *data, int datalen, unsigned char *hmac_origin);
int SplitMessage(char message[], char hash_key[], char hashes[10][65], char message_sig[], char KeyID[], char pubkey[], char ts[], char te[], char cert_sig[], char Mac[], char msg_hash[], char message_receive[], char message_cache[], int num);
int hash_table_delete(struct HashTable_PC* ht, char* key);
#endif
