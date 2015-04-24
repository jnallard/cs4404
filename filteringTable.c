#include "shared.h"


typedef struct ShadowFilteringTableEntry {
	Flow *flow;
	struct timeval* startTime;
	struct ShadowFilteringTableEntry *next;
} ShadowFilteringTableEntry;


ShadowFilteringTableEntry *headTableEntry;
pthread_mutex_t filteringTableLock; //prevent race condition


//This function initialize the head entry in the shadow filtering table
void initializeShadowFilteringTableEntry(){
	headTableEntry = NULL;
	filteringTableLock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
}


//This function adds an entry to the shadow filtering table
void addEntryToShadowFilteringTable(Flow* flow){
	ShadowFilteringTableEntry *entry = (ShadowFilteringTableEntry*)malloc(sizeof(ShadowFilteringTableEntry));

	struct timeval* currentTime = (struct timeval*)malloc(sizeof(struct timeval));
	gettimeofday(currentTime, NULL);

	entry->flow = flow;
	entry->startTime = currentTime;
	entry->next = NULL;

	pthread_mutex_lock(&(filteringTableLock));

	if(headTableEntry == NULL){
		headTableEntry = entry;
	} else {
		ShadowFilteringTableEntry *tmp = headTableEntry;
		while(tmp->next != NULL){
			tmp = tmp->next;
		}
		tmp->next = entry;
	}

	pthread_mutex_unlock(&(filteringTableLock));

}

//This function checks to see if the given flow is already in the shadow filtering table
//by comparing the attacker IP address inside the flow. If it is, return 0; otherwide return 1.
int isInShadowFilteringTable(Flow* flow){
	struct in_addr* attackerIP = flow->attackerIP;
	ShadowFilteringTableEntry *ptr = headTableEntry;
	int doesExist = 1;

	pthread_mutex_lock(&(filteringTableLock));

	while(ptr != NULL){
		if(compareIPAddresses(attackerIP, ptr->attackerIP) == 0){
			doesExist = 0;
			break;
		}
		ptr = ptr->next;
	}

	pthread_mutex_unlock(&(filteringTableLock));

	return doesExist;
}

//This function update the shadow filtering table by removing all entries that 
//are expired
void updateShadowFilteringTable(){
	struct timeval* currentTime = (struct timeval*)malloc(sizeof(struct timeval));
	gettimeofday(currentTime, NULL);

	pthread_mutex_lock(&(filteringTableLock));

	while(headTableEntry != NULL){
		if(hasTimeElapsed(headTableEntry->startTime, T_LONG) == 1) {
			//delete this entry
			ShadowFilteringTableEntry toBeDeleted = headTableEntry;
			headTableEntry = headTableEntry->next;

			freeFlow(toBeDeleted->flow);
			free(toBeDeleted->startTime);
			free(toBeDeleted);

		} else break;
	}

	pthread_mutex_unlock(&(filteringTableLock));

}


//This function compares two ip addresses to see if they are the same, and return 0 if they are.
int compareIPAddresses(struct in_addr* ip1, struct in_addr* ip2){
	char ipStr1[INET_ADDRSTRLEN], ipStr2[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, ip1, ipStr1, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, ip2, ipStr2, INET_ADDRSTRLEN);
	return strcmp(ipStr1, ipStr2);
}
