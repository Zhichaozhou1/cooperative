#include "lab.h"

/*****************************************************************************
 * Function Name: key_init
 * Description: A function for generating a random string as key
 * output: A string
 *
 * Parameter:
 * @ key_origin: random string
 * @ len: length of key
 *
 * Return
 * @ 1: Function Success
 * @ 0: Funtion error
*/
int key_init(unsigned char *key_origin, int len){
        const char dataset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"; //char set used to generate random strings
        int i = 0;
        if (len > 0){
//              key_origin = malloc((len+1)*sizeof(char));
                //Generate a random string as key
                for (i=0; i<len; i++){
                        int index_temp = rand() % (sizeof(dataset)-1);
                        *(key_origin+i) = dataset[index_temp];
                }
//              *(key_origin+len) = '\0';
        } else {
                printf("Length error!\n");
                return False;
        }
        return True;
}

/*****************************************************************************
 * Function Name: generate_key_chain
 * Description: A function for generating a Tesla key chain
 * output: A string array pointer, storing the key chain
 *
 * Parameter:
 * @ key: Original key
 * @ n: the number of key values in a frame (referring to Tesla algorithm)
 * @ key_chain[]: string array to store the output
 *
 * Return
 * @ 1: Function Success
 * Attention:
 * Please allocate memory for the key_chain array in advance so that the program can know the size of it
*/
int generate_key_chain(const unsigned char* key, int n, unsigned char* key_chain[]){
        int i = 0, j = 0;

        //unsigned char char_plus = '1';

        unsigned char* key_temp = (unsigned char*)malloc((hex_cnt_sha256+1) * sizeof(char)); //original K plus a '1' in the end, size=65
        unsigned char* hash_temp = (unsigned char*)malloc(SHA256_DIGEST_LENGTH * sizeof(char)); //store the hash output, size=32
        key_chain[n] = (unsigned char*)malloc((hex_cnt_sha256+1) * sizeof(char)); //store the %02x results of hash
        strcpy(key_chain[n], key); //store the input key value into the last position of key_chain

        //loop for generating the key chain
        for (i=n-1; i>=0; i--){
                key_chain[i] = (unsigned char*)malloc((hex_cnt_sha256+1) * sizeof(char)); //store the %02x results of hash
                strcpy(key_temp, key_chain[i+1]); //the data to be hashed
                //key_temp[hex_cnt_sha256] = char_plus; //append char '1' to the end
                size_t len = strlen(key_temp);
                SHA256((const unsigned char*) key_temp, len, hash_temp); //get the hash output
/*              for (j = 0; j < SHA256_DIGEST_LENGTH ; j++){
                        printf("%02x",hash_temp[j]);
                }
                printf("\n");*/
                //change the hash output to 02x format (64 bytes)
                for (j = 0; j < SHA256_DIGEST_LENGTH ; j++){
                    snprintf(key_chain[i]+2*j, hex_cnt_sha256+1-2*j, "%02x", hash_temp[j]);
                }
		//printf("%s\n",key_chain[i]);
//              key_chain[i][hex_cnt_sha256] = '\0';
        }
        free(key_temp);
        free(hash_temp);
	//printf("%s\n",key_chain[i]);
        return True;
}

/*****************************************************************************
 * Function Name: HMAC_sha256
 * Description: A function for computing HMAC using sha256
 * output: A string
 *
 * Parameter:
 * @ key_origin: secret key
 * @ keylen: length of key (how many char)
 * @ data: the data string to be processed
 * @ datalen: length of data (how many char)
 * @ result: the HMAC result string
 * @ resultlen: length of result
 *
 * Attention:
 * Please allocate memory for result in advance!
*/
unsigned char *HMAC_sha256(const void *key, int keylen, const unsigned char *data, int datalen, unsigned char *result, unsigned int *resultlen) {
    return HMAC(EVP_sha256(), key, keylen, data, datalen, result, resultlen);
}

/*****************************************************************************
 * Function Name: verify_HMAC
 * Description: A function for verifying HMAC
 * output: bool
 *
 * Parameter:
 * @ key_origin: secret key
 * @ keylen: length of key (how many char)
 * @ data: the data string to be processed
 * @ datalen: length of data (how many char)
 * @ hmac_origin: the HMAC to be verified
 *
*/
int verify_HMAC(const void *key, int keylen, const unsigned char *data, int datalen, unsigned char *hmac_origin){
        int flag = 0;
        unsigned char *hmac_computed = NULL; //the HMAC computing result
        hmac_computed = (unsigned char*)malloc(hmac_resultlen*sizeof(char));
        unsigned char *hmac_02x = NULL; //HMAC in 02x format
        hmac_02x = (unsigned char*)malloc((hex_cnt_sha256)*sizeof(char));
        unsigned int HMAC_length = -1;
        HMAC_sha256( key, keylen, data, datalen, hmac_computed, &HMAC_length); //Compute HMAC using given secret key and data
        for (unsigned int j = 0; j < hmac_resultlen; j++){
                snprintf(hmac_02x+2*j, hex_cnt_sha256+1-2*j, "%02x", hmac_computed[j]);
        }

        //Compare the computed HMAC and the received HMAC
        if ( strcmp(hmac_origin, hmac_02x)==0 ){
                flag = True;
        } else {
                flag = False;
        }
        free(hmac_computed);
        free(hmac_02x);
        return flag;
}

/*******************************
 * Codes that test the funcitons above
    int i=0, j=0;
        int len = 64;
        unsigned char *key_origin = (unsigned char *)malloc((len)*sizeof(char));
        key_init(key_origin, len);
        //generate key chain
        unsigned char **key_chain = (unsigned char**)malloc(3*sizeof(unsigned char*));
        for (i=0; i<3; i++){
                key_chain[i] = (unsigned char*)malloc((hex_cnt_sha256) * sizeof(char));
        }
        generate_key_chain(key_origin, 2, key_chain);
        for (i=0; i<3; i++){
                printf("key_chain[%d]:\n",i);
                for (j=0; j<64; j++){
                        printf("%c",key_chain[i][j]);
                }
                printf("\n");
        }
        //compute HMAC
        const unsigned char *data_temp = (const unsigned char *)strdup("Yang");
        unsigned char *hmac_result = (unsigned char*)malloc(hmac_resultlen*sizeof(char));
        unsigned char* hmac_02x = (unsigned char*)malloc((hex_cnt_sha256) * sizeof(char));
        unsigned int resultlen = hmac_resultlen;
        //      HMAC(EVP_sha256(),(const void*)(key_chain[0]), strlen((char*)(key_chain[0])), data_temp, strlen((char*)data_temp), hmac_result, &resultlen);
        HMAC_sha256((const void*)(key_chain[0]), strlen((char*)(key_chain[0])), data_temp, strlen((char*)data_temp), hmac_result, &resultlen);
        printf("Original HMAC:\n");
        for (unsigned int j = 0; j < hmac_resultlen; j++){
                printf("%02hhX", hmac_result[j]); // or just "%02X" if you are not using C11 or later
                snprintf(hmac_02x+2*j, hex_cnt_sha256+1-2*j, "%02x", hmac_result[j]);
        }
//              hmac_02x[hex_cnt_sha256] = '\0';
        printf("\n");
        int verify_hmac = 0;
        verify_hmac = verify_HMAC((const void*)(key_chain[0]), strlen((char*)(key_chain[0])), data_temp, strlen((char*)data_temp), hmac_02x);
        if (verify_hmac == 1){
                printf("Verification success\n");
        } else {
                printf("Verification error\n");
        }
        usleep(10000*1000);
*/
