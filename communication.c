#include "lab.h"

//define socket parameters
//#define Port_des 8888
#define Port_RSU 8888
#define IP_src 192.168.2.1 //source ip address
//#define IP_dest "130.237.20.255"
#define size_message 1024
#define size_queue_max 80000
#define interval_sending_ms 99.777 //Interval between two sending messages
#define BILLION 1000000000.0
#define MILLION 1000000.0
#define THOUSAND 1000.0
#define data_file "msg_delay.txt"
/*Define the structure of socket*/
typedef struct struct_send_sock{
        int sock; //socket descriptor
        struct sockaddr_in addr_this;
        int addr_len_this;
        char* pubkey_addr;
} Sock_this;

typedef struct struct_recv_sock{
        int sock;
        struct sockaddr_in addr_target;
        int addr_len_target;
        int Port_src;
        char* message;
        char* prikey_addr;
        char* pubkey_addr;
} Sock_target;

Sock_this sock_this = {-1};
Sock_target sock_target = {-1};
struct HashTable_PC* ht;
struct HashTable_PC* ht2;
struct HashTable_PC* ht3;
queue *queue_msg_header = NULL; //linked list header
queue *queue_msg_rear = NULL; //linked list rear
queue *queue2_msg_header = NULL; //linked list header
queue *queue2_msg_rear = NULL; //linked list rear
queue *queue3_msg_header = NULL; //linked list header
queue *queue3_msg_rear = NULL; //linked list rear
struct timespec time_PC_gen;
struct timespec time_recv[size_queue_max];
struct timespec time_process[size_queue_max];
struct timespec time_end[size_queue_max];
double msg_delay[size_queue_max];
unsigned char challenge[65] = {'\0'};
int cnt_msg_recv = 0;
int cnt_msg_end = 0;
int valid_msg_end = 0;
int main(int argc, char* argv[]){
        char* message = argv[1];
        char* IP_des = argv[2];
        int Port_src = atoi(argv[3]);
	int Port_des = atoi(argv[4]);
        char* pubkey_addr = argv[5];
        char* prikey_addr = argv[6];
	int sleep,seed;
	seed = atoi(argv[7]);
	srand(seed);
	sleep = rand()%100;
	//printf("%d\n",sleep);
	usleep(sleep*1000);
        init_socket(IP_des,Port_src,Port_des,message,pubkey_addr,prikey_addr);
        Sock_this *socket_this = &sock_this;
        Sock_target *socket_target = &sock_target;
        queue_msg_header = initLink();
        queue_msg_rear = queue_msg_header;
	queue2_msg_header = initLink();
        queue2_msg_rear = queue2_msg_header;
	queue3_msg_header = initLink();
        queue3_msg_rear = queue3_msg_header;
        ht = hash_table_new();
	ht2 = hash_table_new();
	ht3 = hash_table_new();
        strcpy(challenge,rsu_key_initial);
	usleep(1000*1000);
        void *recv_message(void*);
        void *send_message(void*);
        //Create 3 threads
        pthread_t th_recv, th_send, th_process;
        pthread_create(&th_send, NULL, send_message, (void *)socket_target);
        pthread_create(&th_recv, NULL, recv_message, (void *)socket_this);
        pthread_create(&th_process, NULL, process, NULL);
        pthread_join(th_recv, NULL);
        pthread_join(th_send, NULL);
        pthread_join(th_process, NULL);
        return 0;
}

/*Function to initiate sockets*/
int init_socket(char* IP_des,int Port_src, int Port_des, char* message,char* pubkey_addr, char* prikey_addr)
{
        //Create socket descriptor
        struct timespec socket_time;
	clock_gettime(CLOCK_REALTIME, &socket_time);
	sock_this.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        sock_target.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        //Check if creating successfully
        if (sock_this.sock < 0 || sock_target.sock < 0 ){
                printf("Initiating sockets failed.\n");
                exit(1);
        }

        //Set broadcast
        int set = 1;
        if (setsockopt(sock_this.sock, SOL_SOCKET, SO_BROADCAST, &set, sizeof(set)) == -1) {
            printf("setsockopt failed.\n");
            exit(1);
        }
        if (setsockopt(sock_target.sock, SOL_SOCKET, SO_BROADCAST, &set, sizeof(set)) == -1) {
                printf("setsockopt failed.\n");
                exit(1);
        }

        //Set address
        memset(&sock_this.addr_this, 0, sizeof(sock_this.addr_this)); //Clear memory
        memset(&sock_target.addr_target, 0, sizeof(sock_target.addr_target));
        sock_this.addr_this.sin_port = htons(Port_des); //Convert the unsigned short integer from host byte order to network byte order
        sock_this.addr_this.sin_addr.s_addr = INADDR_ANY; //Set the address INADDR_ANY instead of indicating the exact address number
        sock_this.addr_this.sin_family = AF_INET;   //Use IPv4
        sock_this.pubkey_addr = pubkey_addr;

        sock_target.addr_target.sin_port = htons(Port_src);
        sock_target.addr_target.sin_addr.s_addr = inet_addr(IP_des); //Convert the unsigned short integer from host byte order to network byte order
        sock_target.addr_target.sin_family = AF_INET;   //Use IPv4
        sock_target.message = message;
        sock_target.prikey_addr = prikey_addr;
        sock_target.pubkey_addr = pubkey_addr;

        sock_this.addr_len_this = sizeof(struct sockaddr_in);
        sock_target.addr_len_target = sizeof(struct sockaddr_in);
        //Bind the address to the socket referred by the descriptor
	int bReuseaddr=1;
	setsockopt(sock_this.sock,SOL_SOCKET ,SO_REUSEADDR,(const char*)&bReuseaddr,sizeof(int));
        if (bind(sock_this.sock, (struct sockaddr*)&(sock_this.addr_this), sizeof(struct sockaddr)) < 0){
                printf("Bind failed.\n");
                exit(1);
        }
	//sock_this.addr_this.sin_port = htons(Port_RSU);
	//if (bind(sock_this.sock, (struct sockaddr*)&(sock_this.addr_this), sizeof(struct sockaddr)) < 0){
	//	printf("Bind failed.\n");
        //        exit(1);
        //}
	//clock_gettime(CLOCK_REALTIME, &socket_time);
	printf("socket initiated at %ld,%ld\n",socket_time.tv_sec,socket_time.tv_nsec);
        //printf("Sockets initiated!\n");
        return 0;
}

/*Function to receive messages*/
void* recv_message (void *sock){
        Sock_this *sock_this = (Sock_this *)sock;
        struct sockaddr_in addr_others;
        unsigned char hash[32] = {'\0'};
        unsigned char hash_encode[65] = {'\0'};
        unsigned char challenge_recv[65] = {'\0'};
        int hash_len;
        char message_recv[size_message] = {'\0'}; //Buffer storing received messages
	char message[100] = {'\0'};
	char hash_key[65] = {'\0'};
	char hashes[10][65] = {'\0'};
	char message_sig[129] = {'\0'};
	char KeyID[10] = {'\0'};
	char pubkey[129] = {'\0'};
	char ts[10] = {'\0'};
	char te[10] = {'\0'};
	char cert_sig[129] = {'\0'};
	char Mac[129] = {'\0'};
	char msg_hash[65] = {'\0'};
	char message_cache[1024] = {'\0'};
	int num = 10;
	int doespcstore = 0;
	int doesmessagestore = 0;
        while(1){
                int flag;
                flag = recvfrom(sock_this->sock, message_recv, size_message, 0,
                                                                (struct sockaddr *)&addr_others, (socklen_t *)&(sock_this->addr_len_this));
                //the 4th argument is the source IP address
                //recvfrom returns the number of bytes received, but -1 when errors.
                if (flag >= 0){
                        //printf("Message received: %s\n",message_recv);
                        //clock_gettime(CLOCK_REALTIME, &(time_recv[cnt_msg_recv]));
                        //cnt_msg_recv++;
                } else {
                        printf("Receiving failed.\n");
                        exit(1);
                }
                if(strlen(message_recv)<100)//from RSU
                {
			//printf("Message received: %s\n",message_recv);
                        EVP(message_recv,hash,&hash_len);
                        for (int j = 0; j < 32 ; j++){
                                snprintf(hash_encode+2*j, sizeof(hash_encode)-2*j, "%02x", hash[j]);
                        }
                        if(strcmp(hash_encode,challenge)==0)
                        {
                                //printf("challenge update!\n");
                                strcpy(challenge,message_recv);
                        }
                }
                else
                {
                        /*for(int i= 0; i < strlen(message_recv); i++)
                        {
                                if(message_recv[i] != '|')
                                {
                                        challenge_recv[i] = message_recv[i];
                                }
                                else
                                {
                                        break;
                                }
                        }
                        if(strcmp(challenge_recv,challenge)==0)
                        {
                                EVP(message_recv,hash,&hash_len);
                                for (int j = 0; j < 32 ; j++){
                                        snprintf(hash_encode+2*j, sizeof(hash_encode)-2*j, "%02x", hash[j]);
                                }
                                if(hash_encode[63]=='0'&&hash_encode[62]=='0')//&&(digest_encode[61]=='0'))
                                {
                                        printf("pre-authentication pass!");
                                        queue_msg_rear = insertElem(queue_msg_rear, message_recv);
                                        //clock_gettime(CLOCK_REALTIME, &(time_recv[cnt_msg_recv]));
                                        cnt_msg_recv++;
                                }
                        }*/
			SplitMessage(message, hash_key, hashes, message_sig, KeyID, pubkey, ts, te, cert_sig, Mac, msg_hash, message_recv, message_cache, num);
			doespcstore = hash_table_get(ht, KeyID, pubkey);
			if (doespcstore == 0)
			{
				queue_msg_rear = insertElem(queue_msg_rear, message_recv);
				hash_table_input(ht,KeyID,ts,te,pubkey,message_cache,Mac);
				hash_table_input(ht2,msg_hash,ts,te,pubkey,message_cache,Mac);
			}
			else
			{
				int flag_tesla = 0;
                		unsigned char message_cache_previous[1024] = {'\0'};
                		unsigned char message_cache_mac[1024] = {'\0'};
                		doesmessagestore = hash_table_get_message(ht, KeyID, message_cache_previous, message_cache_mac);
                		if(doesmessagestore == 1)
				{
					flag_tesla = verify_HMAC((const void*)hash_key, strlen((char*)hash_key), message_cache_previous, strlen((char*)message_cache_previous), (char*)message_cache_mac);
                		}
				/*else
				{
					hash_table_input(ht,KeyID,ts,te,pubkey,message_cache,Mac);
					hash_table_input(ht2,msg_hash,ts,te,pubkey,message_cache,Mac);
				}*/
				if(flag_tesla == 1)
                		{
                        		printf("TESLA success!\n");
                        		//printf("%s\n",message_cache_mac);
                        		//hash_table_input(ht,KeyID,ts,te,pubkey,message_cache,Mac);
					//hash_table_input(ht2,msg_hash,ts,te,pubkey,message_cache,Mac);
                		}
				queue_msg_rear = insertElem(queue_msg_rear, message_recv);
				hash_table_input(ht,KeyID,ts,te,pubkey,message_cache,Mac);
                                hash_table_input(ht2,msg_hash,ts,te,pubkey,message_cache,Mac);
			}

                }
        }
        close(sock_this->sock);
}

/*Function to send messages*/
void* send_message (void*sock){
        char beacon_send[1024] = {'\0'};
        Sock_target *sock_target = (Sock_target *)sock;
        char* message_send = sock_target->message;
	int message_num = atoi(message_send);
        struct timespec last_send;
	struct timespec time_now;
	clock_gettime(CLOCK_REALTIME, &last_send);
	double sending_cost=0;
	double solution_delay[8000];
	int num=0;
	unsigned char *key_origin = NULL;
        int len = 64;
        key_origin = malloc((len+1)*sizeof(char));
	unsigned char* tesla_key_chain[600];
	unsigned char tesla_key_send[65]={'\0'};
        unsigned char tesla_key_use[65]={'\0'};
	for(int i=0;i<100;i++){tesla_key_chain[i]=malloc(64*sizeof(char));}
	//int number=0;
	//printf("%s\n",message_send);
        char message_base64_send[size_message] = {'\0'};
        PCGen(sock_target->prikey_addr,sock_target->pubkey_addr);
	int seed = message_num;
	srand(seed);
	int msg_num = rand()%600;
	int sleep = 0;
	//int sleep = rand()%100;
	//clock_gettime(CLOCK_REALTIME, &last_send);
        //printf("%dth message send at:%ld.%ld\n",num,last_send.tv_sec,last_send.tv_nsec);
	//BaseLineSendMain(message_send, message_base64_send); //Generate and get the whole Base64 message
        while(1){
		if(num%599==0)
		{
			PCGen(sock_target->prikey_addr,sock_target->pubkey_addr);
			//printf("PC regen\n");
			key_init(key_origin, len);//generate tesla key chain
                        generate_key_chain(key_origin, 600, tesla_key_chain);
			//printf("%s\n", tesla_key_chain[1]);
			sleep = rand()%100;
			num = 0;
		}
		strcpy(tesla_key_send,tesla_key_chain[num%600]);
                strcpy(tesla_key_use,tesla_key_chain[num%600+1]);
		num++;
                strcpy(beacon_send,challenge);
                strcat(beacon_send,"|");
                strcat(beacon_send,message_send);
		strcat(beacon_send,"|");
		strcat(beacon_send,tesla_key_send);
                solution_delay[num-1] = message_sign(beacon_send,message_base64_send,tesla_key_use,1,sock_target->prikey_addr,sock_target->pubkey_addr);
		//usleep(39.2*1000);
		clock_gettime(CLOCK_REALTIME, &time_now);
                sending_cost=(time_now.tv_sec-last_send.tv_sec)*1000.0+(time_now.tv_nsec-last_send.tv_nsec)/1000000.0;
		usleep((interval_sending_ms+sleep-sending_cost)*1000);
		sleep = 0;
		//printf("%f\n",sending_cost);
		clock_gettime(CLOCK_REALTIME, &last_send);
		if (sendto(sock_target->sock, message_base64_send, strlen(message_base64_send)+1, 0,
                                (struct sockaddr *)&(sock_target->addr_target), sock_target->addr_len_target )  < 0){
                        printf("Sending failed.\n");
                        //printf("Error sending packet: Error %d.\n", errno);
                        exit(1);
                }
		//number++;
		//printf("%d\n",number);
		//clock_gettime(CLOCK_REALTIME, &last_send);
		//printf("%dth message send at:%ld.%ld\n",num,last_send.tv_sec,last_send.tv_nsec);
		//clock_gettime(CLOCK_REALTIME, &last_send);
		//printf("%dth message send at:%ld.%ld!\n",num,last_send.tv_sec,last_send.tv_nsec);
		printf("%dth message send:%s\n",num,message_base64_send);
                //usleep(interval_sending_ms*1000);
		/*if(num==1200)
		{
			double sum = 0;
			double avg_delay = 0;
			for(int i=0; i<num; i++)
			{
				sum = sum+=solution_delay[i];
			}
			avg_delay = sum/num;
			printf("%f\n",avg_delay);
		}*/
        }
        close(sock_target->sock);
}

void *process(){
        int num=0;
	int hash_num = 5;
	queue *temp;
	queue *temp_plus;
	char *msg_temp;
	char message[100] = {'\0'};
        char hash_key[65] = {'\0'};
        char hashes[10][65] = {'\0'};
        char message_sig[129] = {'\0'};
        char KeyID[10] = {'\0'};
        char pubkey[129] = {'\0'};
        char ts[10] = {'\0'};
        char te[10] = {'\0'};
        char cert_sig[129] = {'\0'};
        char Mac[129] = {'\0'};
        char msg_hash[65] = {'\0'};
        char message_cache[1024] = {'\0'};
        while(1){
                int expire=0;
                //Skip the process if there is no message in the linked list (header->next is NULL)
                if (queue2_msg_header->next==NULL){
                        if(queue_msg_header->next==NULL)
			{
				continue;
                	}
			else
			{
				temp = queue_msg_header;
                		temp_plus = queue_msg_header;
                		msg_temp = temp->next->str;
			}
		}
		else
		{
			temp = queue2_msg_header;
                	temp_plus = queue2_msg_header;
                	msg_temp = temp->next->str;
		}
		SplitMessage(message, hash_key, hashes, message_sig, KeyID, pubkey, ts, te, cert_sig, Mac, msg_hash, msg_temp, message_cache, num);
                clock_gettime(CLOCK_REALTIME, &(time_process[cnt_msg_end]));
                //queue *temp = queue_msg_header;
                //queue *temp_plus = queue_msg_header;
                //char *msg_temp = temp->next->str;
                int flag = 0;
                if(((time_process[cnt_msg_end].tv_sec - time_recv[cnt_msg_end].tv_sec)*1000 + (time_process[cnt_msg_end].tv_nsec - time_recv[cnt_msg_end].tv_nsec)/MILLION)<1000)
                {
                        flag = message_process(msg_temp, ht, ht2, ht3, hash_num, queue2_msg_rear, queue3_msg_header); //Verify messages
			//printf("1\n");
                }
                if (flag == 1){
                        num++;
                        printf("Verification successful!\n");
			//hash_table_input(ht3,KeyID,ts,te,pubkey,message_cache,Mac);
                } else if (flag == 0){
                        num++;
                        printf("Verification failed!\n");
                } else if (flag == -1){
                        printf("Other errors.\n");
                }
                //Get the end time of messages
                clock_gettime(CLOCK_REALTIME, &(time_end[cnt_msg_end]));
                if(flag==1){
                        msg_delay[valid_msg_end] = (time_end[cnt_msg_end].tv_sec- time_recv[cnt_msg_end].tv_sec)*1000 + (time_end[cnt_msg_end].tv_nsec - time_recv[cnt_msg_end].tv_nsec)/MILLION;
                        valid_msg_end++;
                }
                cnt_msg_end++;
                int cnt_nodes = 0;
                while (temp_plus->next != NULL){
                        cnt_nodes++;
                        temp_plus = temp_plus->next;
                }
                queue_msg_header = queue_msg_header->next;
                queue_msg_header->str = NULL;
                free(temp);
                if (valid_msg_end==100){
                        FILE *fp = fopen(data_file, "wb");
                        for (int i = 0; i < valid_msg_end; i++) {
                            fprintf(fp, "%d %fms\n", i, msg_delay[i]);
                            // check for error here too
                        }
                        fclose(fp);
                }
        }
}

queue * initLink(){
        queue * p=(queue*)malloc(sizeof(link));//create the header
        p->str = NULL;
        p->next = NULL;
        return p;
}

/*Function to insert element*/
queue * insertElem(queue * p,char* msg){
        queue * temp=(queue*)malloc(sizeof(queue));
        char *msg_temp = (char *)malloc((strlen(msg)+1)*1);
        strcpy(msg_temp, msg);
        temp->str = msg_temp;
        temp->next = NULL;
        p->next = temp;
        p=p->next;
        return  p;
}
