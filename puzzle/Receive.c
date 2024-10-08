#include "lab.h"


int message_process(unsigned char base64_receive[], struct HashTable_PC* ht)
{
	struct timespec time1;
	struct timespec time2;
	struct timespec time3;
	struct timespec time4;
	struct timespec time5;
        struct timespec time6;
	double process1, process2, process3, process4;
        int i,j;
        char PC_store[1024] = {'\0'};
        char PC_store_KeyID[10] = {'\0'};
        char PC_received_KeyID[10] = {'\0'};
        char* PC_st;
        //unsigned char challenge[1024] = {'\0'};
        char message[1024] = {'\0'};
	char msg_flag[100] = {'\0'};
        char hash_key[65] = {'\0'};
	char message_sig[1024] = {'\0'};
        char KeyID[10] = {'\0'};
        char pubkey[1024] = {'\0'};
        char ts[1024] = {'\0'};
        char te[1024] = {'\0'};
        char cert_sig[1024] = {'\0'};
	char mID[10] = {'\0'};
        char zero_buffer[1024] = {'\0'};
	SplitMessage(base64_receive, message, msg_flag, hash_key, message_sig, KeyID, pubkey, ts, te, cert_sig, mID);
        /* Construct PC base64 message */
        unsigned char separator[2] = {'|'};
        unsigned char PC_base64[1024] = {'\0'};     // The PC_decode is the base64 PC without "|"
        /* Decode mesage */
        int message_sig_decode_len = 0;
        int KeyID_decode_len = 0;
        int pubkey_decode_len = 0;
        int ts_decode_len = 0;
        int te_decode_len = 0;
        int cert_sig_decode_len = 0;
        unsigned char message_decode[1024] = {'\0'};
        unsigned char message_sig_decode[1024] = {'\0'};
        unsigned char KeyID_decode[1024] = {'\0'};
        unsigned char pubkey_decode[1024] = {'\0'};
        unsigned char ts_decode[1024] = {'\0'};
        unsigned char te_decode[1024] = {'\0'};
        unsigned char cert_sig_decode[1024] = {'\0'};
	struct timespec time_valid;
        //strcpy(message_decode, challenge);
        //strcat(message_decode, "|");
	clock_gettime(CLOCK_REALTIME, &time1);
        strcpy(message_decode, message);
	strcat(message_decode, "|");
	strcat(message_decode, msg_flag);
	strcat(message_decode, "|");
	strcat(message_decode, hash_key);
	//strcat(message_decode, "|");
        int message_decode_len = strlen(message_decode);
        message_sig_decode_len = base64_decode(message_sig, strlen(message_sig), message_sig_decode);
        KeyID_decode_len = base64_decode(KeyID, strlen(KeyID), KeyID_decode);
        pubkey_decode_len = base64_decode(pubkey, strlen(pubkey), pubkey_decode);
        strcpy(ts_decode, ts);
        ts_decode_len = strlen(ts_decode);
        strcpy(te_decode, te);
        te_decode_len = strlen(te_decode);
        cert_sig_decode_len = base64_decode(cert_sig, strlen(cert_sig), cert_sig_decode);
	clock_gettime(CLOCK_REALTIME, &time2);
	//printf("%s,%s,%s,%s,%s\n",KeyID,pubkey,ts,te,cert_sig);
        //printf("Received message is:\n%s\n", message_decode);
        int doespcstore = 0;
        int times = 1;
        doespcstore = hash_table_get_pubkey(ht,KeyID,pubkey);
	clock_gettime(CLOCK_REALTIME, &time3);
	pubkey_decode_len = base64_decode(pubkey, strlen(pubkey), pubkey_decode);
	//clock_gettime(CLOCK_REALTIME, &time3);
        if (doespcstore == 0)                             // If PCSave is not same as PC receive
        {/* Verify Signatuer, if correct save as PCSave */
                /* Get system time */
                struct timespec time_now;
                clock_gettime(CLOCK_REALTIME, &time_now);
                time_t t = time_now.tv_sec;     // Get current time from 1970-01-01, count on seconds
                int t_current = time(&t) / 60;                              // start time, count on minutes
                int ts_int = atoi(ts);
                int te_int = atoi(te);
                if((t_current < ts_int) || (t_current > te_int))            // Check if certificate is valid
                {
                        printf("Certificate expired.\n");
                        return 0;
                }
                /* Construct pseudonym for verify */
                int pseudonym_len;
                pseudonym_len = KeyID_decode_len + ts_decode_len + te_decode_len + pubkey_decode_len;
                unsigned char pseudonym[pseudonym_len+1];
                for(i = 0; i < 4; i++)
                {
                        pseudonym[i] = KeyID_decode[i];
                }
                for(i = 4, j = 0; j < ts_decode_len; i++, j++)
                {
                        pseudonym[i] = ts_decode[j];
                }
                for(i = 4 + ts_decode_len, j = 0; j < te_decode_len; i++, j++)
                {
                        pseudonym[i] = te_decode[j];
                }
                for(i = 4 + ts_decode_len + te_decode_len, j = 0; j < pubkey_decode_len; i++, j++)
                {
                        pseudonym[i] = pubkey_decode[j];
                }
		pseudonym[pseudonym_len] = '\0';
		//printf("%02x\n",pseudonym);
                /* read CA's public key from CA certificate*/
                FILE *f = fopen("ca.pem", "r");
                X509 *x_509 = PEM_read_X509(f, NULL, NULL, NULL);
                fclose(f);
                if (x_509 == NULL)
                {
                        printf("Error：PEM_read_X509()\n");
                        return 0;
                }
                EVP_PKEY *evp_pkey = X509_get_pubkey(x_509);
                if (evp_pkey == NULL)
                {
                        printf("Error：X509_get_pubkey()\n");
                        return 0;
                }
                EC_KEY *cert_ec_key = EVP_PKEY_get1_EC_KEY(evp_pkey);
                if (cert_ec_key == NULL)
                {
                        printf("Error：EVP_PKEY_get1_EC_KEY()\n");
                        return 0;
                }
                /* Verify PC signature */
                int PCresult;
                PCresult = verify(cert_ec_key, cert_sig_decode, cert_sig_decode_len, pseudonym);
                switch (PCresult)
                {
                case 0:
                        //printf("Pseudonym Certificate Signature Invalid.\n");                              // Return 0 if verification failed
                        return 0;
                        break;
                case -1:
                        printf("Pseudonym Certificate Signature Verification Error.\n");
                        return 0;
                        break;
                case 1:
                        //printf("Pseudonym Certificate Signature Verification Successful.\n");                 // Keep running if verification success
                        clock_gettime(CLOCK_REALTIME, &time_valid);
			//printf("%s,%s,%s,%s\n",KeyID,ts,te,pubkey);
                        hash_table_input(ht,KeyID, KeyID, ts, te, pubkey, hash_key, time_valid);
                        break;
                default:
                        break;
                }
        }
        else        // Use PCSave to verify Beacon Signature
        {
                //printf("Received PC already saved, then skip PC verification!\n");
                //pubkey_decode_len = base64_decode(pubkey, strlen(pubkey), pubkey_decode);
        }
        /* Write public key into EC_key format */
        EC_KEY *ec_key;
        EC_GROUP *ec_group;
        unsigned char *pp = pubkey_decode;
        if ((ec_key = EC_KEY_new()) == NULL)
        {
                printf("Error：EC_KEY_new()\n");
                return 0;
        }
        if ((ec_group = EC_GROUP_new_by_curve_name(NID_brainpoolP256r1)) == NULL)
        {
                printf("Error：EC_GROUP_new_by_curve_name()\n");
                EC_KEY_free(ec_key);
                return 0;
        }

        int ret = EC_KEY_set_group(ec_key, ec_group);
        if (ret != 1)
        {
                printf("Error：EC_KEY_set_group\n");
                EC_KEY_free(ec_key);
                return 0;
        }
//    ec_key = o2i_ECPublicKey(&ec_key, (const unsigned char **)&pp, strlen(pubkey_decode));
        ec_key = o2i_ECPublicKey(&ec_key, (const unsigned char **)&pp, pubkey_decode_len);
        if (ec_key == NULL)
        {
                printf("Error：o2i_ECPublicKey\n");
                EC_KEY_free(ec_key);
                return 0;
        }
        clock_gettime(CLOCK_REALTIME, &time4);
	/* Verify beacon message */
        int Beacon_result;
        Beacon_result = verify(ec_key, message_sig_decode, message_sig_decode_len, message_decode);
        switch (Beacon_result)
        {
        case 0:
                printf("Beacon Signature Invalid.\n");
                return 0;
                break;
        case -1:
                printf("Beacon Signature Verification Error.\n");
                return 0;
                break;
        case 1:
                //printf("Beacon Verification Success.\n");
		//hash_table_input(ht3,KeyID,KeyID,ts,te,pubkey,message_cache,Mac);
		/*for(int hash_index = 0; hash_index++; hash_index<num)
		{
			if(hash_table_get_pubkey(ht2, hashes[hash_index], KeyID_cooperative) == 1)
			{
				if(hash_table_get_pubkey(ht,KeyID_cooperative,pubkey_cooperative) == 1)
				{
					hash_table_get_message(ht2, hashes[hash_index], message_cache_cooperative, Mac_cooperative);
					insertElem(queue2_msg_rear, message_cache_cooperative);
					//hash_table_delete(ht2, hashes[hash_index]);
				}
			}
			hash_table_delete(ht2, hashes[hash_index]);
		}*/
                break;
        default:
                break;
        }
	clock_gettime(CLOCK_REALTIME, &time5);
	process1 = (time2.tv_sec - time1.tv_sec)*THOUSAND + (time2.tv_nsec - time1.tv_nsec)/MILLION;
	process2 = (time3.tv_sec - time2.tv_sec)*THOUSAND + (time3.tv_nsec - time2.tv_nsec)/MILLION;
	process3 = (time4.tv_sec - time3.tv_sec)*THOUSAND + (time4.tv_nsec - time3.tv_nsec)/MILLION;
	process4 = (time5.tv_sec - time4.tv_sec)*THOUSAND + (time5.tv_nsec - time4.tv_nsec)/MILLION;
	//printf("%f,%f,%f,%f\n",process1,process2,process3,process4);
        return 1;
}

/*****************************************************************************
 * Function Name: base64_decode
 * Description: Decode message in Base64 format, the encode message ended with '|'
 * @ in_str:  Input string
 * @ in_len:  Input string length
 * @ out_str: Decode message buffer
 *
 * Return
 * @ size: Decode message length
 * @ 0: Function Error
*/

int base64_decode(char in_str[], int in_len, char out_str[])
{
        BIO *b64, *bio;
        BUF_MEM *bptr = NULL;
        int counts;
        int size = 0;
        if (in_str == NULL || out_str == NULL)
                return -1;
        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

        bio = BIO_new_mem_buf(in_str, in_len);
        bio = BIO_push(b64, bio);

        size = BIO_read(bio, out_str, in_len);
        out_str[size] = '\0';

        BIO_free_all(bio);
        return size;
}

/*****************************************************************************
 * Function Name: SignMain
 * Description: Main function for signatuer
 *
 * Parameter
 * @ ec_key:    Private key for verify
 * @ sig:       Signature storage buffer
 * @ siglen:    Signature length
 * @ message: Message used for signature
 *
 * Return
 * @ 1: Function success
 * @ 0: Function error
*/

int verify(EC_KEY *ec_key, const unsigned char *sig, int siglen, unsigned char message[])
{

        int ret;
        unsigned char digest[32]={};
        unsigned int digest_len = 0;
	char hash_encode[100] = {'\0'};

        if(!EVP(message, digest, &digest_len))
        {
                printf("Error：EVP\n");
                return 0;
        }
	/*for (int j = 0; j < 32 ; j++){
                snprintf(hash_encode+2*j, sizeof(hash_encode)-2*j, "%02x", digest[j]);
        }
	printf("%s\n",hash_encode);*/
        /* verify the signature signed by CA's private key */
        ret = ECDSA_verify(0, digest, digest_len, sig, siglen, ec_key);
        return ret;
}

/**********************************************************
 *Function Name: SplitMessage
 *Description: Split received messages
 *char Message
 *char flag: 0~from RSU, other~from OBU the index of the key on the hash chain
 *char hash_key key chain pre-validation
 *char message_sig signature
 *char KeyID
 *char pubkey public key
 *char ts,te
 *char cert_sig signature
 *char mID message ID
*/

int SplitMessage(char message_receive[], char message[], char flag[], char hash_key[], char message_sig[], char KeyID[], char pubkey[], char ts[], char te[], char cert_sig[], char mID[])
{
	int i = 0;
	int j = 0;
	int n = 0;
	/*for(i = 0, j = 0; i < strlen(message_receive); i++, j++)
        {
                if(message_receive[i] != '|')
                {
                        challenge[j] = message_receive[i];
                }
                else
                {
                        i++;
                        break;
                }
        }*/
        for(i = 0, j = 0; i < strlen(message_receive); i++, j++)
        {
                if(message_receive[i] != '|')
                {
                        message[j] = message_receive[i];
                }
                else
                {
                        i++;
                        break;
                }
        }
	for(i, j = 0; i < strlen(message_receive); i++, j++)
        {
                if(message_receive[i] != '|')
                {
                        flag[j] = message_receive[i];
                }
                else
                {
                        i++;
                        break;
                }
        }
	for(i, j = 0; i < strlen(message_receive); i++, j++)
        {
                if(message_receive[i] != '|')
                {
                        hash_key[j] = message_receive[i];
		}
                else
                {
			i++;
                	break;
                }
        }
        for(i, j = 0; i < strlen(message_receive); i++, j++)
        {
                if(message_receive[i] != '|')
                {
                        message_sig[j] = message_receive[i];
                }
                else
                {
                        i++;
	                break;
                }
        }
        for(i, j = 0; i < strlen(message_receive); i++, j++)
        {
                if(message_receive[i] != '|')
                {
                        KeyID[j] = message_receive[i];
		}
                else
                {
	                i++;
        	        break;
                }
        }
        for(i, j = 0; i < strlen(message_receive); i++, j++)
        {
                if(message_receive[i] != '|')
                {
                        pubkey[j] = message_receive[i];
		}
                else
                {
                        i++;
                        break;
                }
        }
        for(i, j = 0; i < strlen(message_receive); i++, j++)
        {
                if(message_receive[i] != '|')
                {
                        ts[j] = message_receive[i];
                }
                else
                {
                        i++;
                        break;
                }
        }
        for(i, j = 0; i < strlen(message_receive); i++, j++)
        {
                if(message_receive[i] != '|')
                {
                        te[j] = message_receive[i];
		}
                else
                {
                        i++;
                        break;
                }
        }
        for(i, j = 0; i < strlen(message_receive); i++, j++)
        {
                if(message_receive[i] != '|')
                {
                        cert_sig[j] = message_receive[i];
		}
                else
                {
                        i++;
                        break;
                }
        }
	for(i, j = 0; i < strlen(message_receive); i++, j++)
        {
                if(message_receive[i] != '|')
                {
                        mID[j] = message_receive[i];
                }
                else
                {
                        i++;
                        break;
                }
        }
	return 1;
}


