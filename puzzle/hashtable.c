#include "lab.h"

static unsigned int hash_33(char* key)
{
        unsigned int hash = 0;
        while (*key) {
                hash = (hash << 5) + hash + *key++;
        }
        //printf("%d ",hash);
        return hash;
}

struct HashTable_PC* hash_table_new()
{
        struct HashTable_PC* ht = (struct HashTable_PC*)calloc(1,sizeof(struct HashTable_PC));
        if (NULL == ht) {
                return NULL;
        }
        ht->table = (struct valid_PC**)calloc(TABLE_SIZE,sizeof(struct valid_PC*));
        if (NULL == ht->table) {
                return NULL;
        }
        //memset(ht->table, 0, sizeof(struct valid_PC*) * TABLE_SIZE);
        return ht;
}

int hash_table_input(struct HashTable_PC* ht, unsigned char* key, unsigned char* KeyID, unsigned char* ts, unsigned char* te, unsigned char* pubkey, unsigned char* hash_key, struct timespec time_recv){
        int i = hash_33(key) % TABLE_SIZE;
        struct valid_PC* p = ht->table[i];
        struct valid_PC* prep = p;
        struct valid_PC* ps = p;
        char* keystr = malloc(strlen(key)+1);
	char* KeyIDstr = malloc(strlen(KeyID)+1);
        char* tsstr = malloc(strlen(ts)+1);
        char* testr = malloc(strlen(te)+1);
        char* pubkeystr = malloc(strlen(pubkey)+1);
	char* hash_keystr = malloc(strlen(hash_key)+1);
        struct valid_PC* valid_PC = (struct valid_PC*)calloc(1,sizeof(struct valid_PC));
        valid_PC->next == NULL;
        strcpy(keystr,key);
	strcpy(KeyIDstr,KeyID);
        strcpy(tsstr,ts);
        strcpy(testr,te);
        strcpy(pubkeystr,pubkey);
	strcpy(hash_keystr,hash_key);
        valid_PC->key = keystr;
	valid_PC->KeyID = KeyIDstr;
        valid_PC->ts = tsstr;
        valid_PC->te = testr;
        valid_PC->pubkey = pubkeystr;
	valid_PC->hash_key = hash_keystr;
	valid_PC->time_recv = time_recv;
        while(p!=NULL)
        {
                prep = p;
		if(strcmp(p->key,key) == 0)
		{
			free(p->hash_key);
			p->hash_key = strdup(hash_keystr);
            		return 0;
		}
                p = p->next;
        }
        if(!ps)
        {
                ht->table[i] = valid_PC;
        }
        else
        {
                prep->next = valid_PC;
        }
        return 0;
}

int hash_table_input_MID(struct HashTable_PC* ht, unsigned char* key, unsigned char* message, struct timespec time_recv){
        int i = hash_33(key) % TABLE_SIZE;
        struct valid_PC* p = ht->table[i];
        struct valid_PC* prep = p;
        struct valid_PC* ps = p;
        char* keystr = malloc(strlen(key)+1);
        char* KeyIDstr = malloc(strlen(message)+1);
        struct valid_PC* valid_PC = (struct valid_PC*)calloc(1,sizeof(struct valid_PC));
        valid_PC->next == NULL;
        strcpy(keystr,key);
        strcpy(KeyIDstr,message);
        valid_PC->key = keystr;
        valid_PC->KeyID = KeyIDstr;
	valid_PC->time_recv = time_recv;
        while(p!=NULL)
        {
                prep = p;
                if(strcmp(p->key,key) == 0)
                {
                        free(p->KeyID);
                        p->KeyID = strdup(KeyIDstr);
                        return 0;
                }
                p = p->next;
        }
        if(!ps)
        {
                ht->table[i] = valid_PC;
        }
        else
        {
                prep->next = valid_PC;
        }
        return 0;
}



int hash_table_get_pubkey(struct HashTable_PC* ht, char* key, char* pubkey){
        int i = hash_33(key) % TABLE_SIZE;
        //printf("%d ",i);
        //fflush(stdout);
        int num=0;
        struct valid_PC* p = ht->table[i];
        while(p)
        {
                //printf("%d\n",num);
                //num++;
                //printf("%d\n",num);
                //printf("1");
                //fflush(stdout);
                if (strcmp(p->key,key) == 0) {
                        strcpy(pubkey,p->pubkey);
                        return 1;
                }
                if(p->next!=NULL)
                {
                        p = p->next;
                }
                else
                {
                        return 0;
                }
        }
        //printf("!\n");
        //printf("%d\n",num);
        //printf("\n");
        return 0;
}


int hash_table_get_KeyID(struct HashTable_PC* ht, char* key, char* KeyID){
        int i = hash_33(key) % TABLE_SIZE;
        int num=0;
        struct valid_PC* p = ht->table[i];
        while(p)
        {
                if (strcmp(p->key,key) == 0) {
                        strcpy(KeyID,p->KeyID);
                        return 1;
                }
                if(p->next!=NULL)
                {
                        p = p->next;
                }
                else
                {
                        return 0;
                }
        }
        return 0;
}

int hash_table_get_hashkey(struct HashTable_PC* ht, char* key, char* hash_key){
        int i = hash_33(key) % TABLE_SIZE;
        int num=0;
        struct valid_PC* p = ht->table[i];
        while(p)
        {
                if (strcmp(p->key,key) == 0) {
                        strcpy(hash_key,p->hash_key);
                        return 1;
                }
                if(p->next!=NULL)
                {
                        p = p->next;
                }
                else
                {
                        return 0;
                }
        }
        return 0;
}

int hash_table_get_time(struct HashTable_PC* ht, char* key, struct timespec* time_recv){
        int i = hash_33(key) % TABLE_SIZE;
        int num=0;
        struct valid_PC* p = ht->table[i];
        while(p)
        {
                if (strcmp(p->key,key) == 0) {
                        //strcpy(hash_key,p->hash_key);
			*time_recv = p -> time_recv;
                        return 1;
                }
                if(p->next!=NULL)
                {
                        p = p->next;
                }
                else
                {
                        return 0;
                }
        }
        return 0;
}

int hash_table_delete(struct HashTable_PC* ht, char* key)
{
    if (ht == NULL || key == NULL) return -1;
    int index = hash_33(key) % TABLE_SIZE;
    struct valid_PC *current = ht->table[index];
    struct valid_PC *prev = NULL;
    while (current != NULL) {
        if (strcmp(current->key, key) == 0) {
            if (prev) {
                prev->next = current->next;
            } else {
                ht->table[index] = current->next;
            }
            free(current->KeyID);
            free(current->ts);
            free(current->te);
            free(current->pubkey);
            free(current->hash_key);
            free(current);
            return 0;
        }
        prev = current;
        current = current->next;
    }
    return -1;
}
