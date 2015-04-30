#include "shared.h"

//This function lets the program sleep for the given milliseconds time
void waitMilliseconds(int millisecondsToWait){
	usleep(millisecondsToWait * 1000);

}

//This function checks if the time has elapsed, return 0 if the start time plus the given milliseconds
//is less than the current time
int hasTimeElapsed(struct timeval* startTime, int milliseconds){
	struct timeval currentTime;
	gettimeofday(&currentTime, NULL);
	double currentTimeInMill = currentTime.tv_sec * 1000 + (currentTime.tv_usec) / 1000;
	double expectedTime = startTime->tv_sec * 1000 + (startTime->tv_usec) / 1000 + milliseconds;
	//return TRUE if the time has passed, otherwise return FALSE
	int returnVal = (currentTimeInMill - expectedTime > 0) ? TRUE : FALSE;
	return returnVal;
}


//This function creates the first route record by providing IP address and the random value
RouteRecord* createRouteRecord(struct in_addr* ipAddress, long randomValue){
	//create the first slot
	RouteRecordSlot *rrSlot = (RouteRecordSlot *)malloc(sizeof(RouteRecordSlot));
	rrSlot->ipAddress = ipAddress;
	rrSlot->randomValue = randomValue;

	//create the route record
	RouteRecord *rr = (RouteRecord *)malloc(sizeof(RouteRecord));
	rr->index = 2;
	rr->size = 4;
	rr->slot1 = rrSlot;

	//assign other slots to null
	rr->slot2 = NULL;
	rr->slot3 = NULL;
	rr->slot4 = NULL;

	return rr;

}


void addGatewayInfo(RouteRecord* routeRecord, struct in_addr* ipAddress, long randomValue){
	RouteRecordSlot *rrSlot = (RouteRecordSlot *)malloc(sizeof(RouteRecordSlot));
	rrSlot->ipAddress = ipAddress;
	rrSlot->randomValue = randomValue;

	RouteRecordSlot **slotPointer = NULL;
	short index = routeRecord->index;
	if(index == 2){
		slotPointer = &(routeRecord->slot2);
	} else if(index == 3){
		slotPointer = &(routeRecord->slot3);
	} else if(index == 4){
		slotPointer = &(routeRecord->slot4);
	}

	if(index < 2 || index > 4){
		printf("Error with routeRecord, index number is %d\n", index);
		exit(1);
	}
	if(slotPointer == NULL){
		printf("Error with routeRecord, slot pointer is null.\n");
		exit(1);
	}

	*slotPointer = rrSlot; 
	(routeRecord->index)++;

}

//This function creates a flow struct from the passed in parameters Ip,
Flow* createFlowStruct(struct in_addr* victimIP, struct in_addr* attackerIP, 
		RouteRecord* routeRecord, int nonce1, int nonce2, int messageType){

	Flow *flow = (Flow *)malloc(sizeof(Flow));
	flow->attackerIP = attackerIP;
	flow->victimIP = victimIP;
	flow->nonce1 = nonce1;
	flow->nonce2 = nonce2;
	flow->messageType = messageType;
	flow->routeRecord = routeRecord;
	return flow;

}

//This function is used to send flow struct over the network  
//Returns the socket file descriptor so communicate can still be looked at.
int sendFlow(char* destIP, int port, Flow* flow){
	// int sockfd;

	int sockfd;
	struct addrinfo hints, *res;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	char portStr[15];
	sprintf(portStr, "%d", port);

	if(getaddrinfo(destIP, portStr, &hints, &res) != 0){ 
		printf("Error in getaddrinfo() when sending complaint\n");
		return -1;
	}

	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if(sockfd < 0) {
		printf("Error in socket() when sending complaint\n");
		return -1;
	}

	if(connect(sockfd, res->ai_addr, res->ai_addrlen) != 0){
		printf("Error in connect() when sending complaint. Error: [%s]\n", strerror(errno));

		return -1;
	}

	sendFlowWithOpenConnection(sockfd, flow);

	return sockfd;

}

int sendFlowWithOpenConnection(int connectionFd, Flow* flow){
	int returnval = 0;
	char* flowString = writeFlowStructAsNetworkBuffer(flow);

	if((returnval = send(connectionFd, flowString, MAX_FLOW_SIZE, 0)) < 0){
		printf("Error occurred when sending request\n");
	} else {
		printf("Request sent\n");
	}

	return returnval;
}


Flow* receiveFlowWithOpenConnection(int connectionFd){

 	char buf[2000];
 	int count;
 	memset(buf, 0, MAX_FLOW_SIZE + 10);
 	count = recv(connectionFd, buf, MAX_FLOW_SIZE, 0);

 	//Nothing Received
 	if(count == 0){
 		return NULL;
 	}

 	buf[count] = '\0';
 	printf("count number %d\n", count);
 	printf("packet received.\n");

 	//handle AITF message
	Flow *receivedFlow = readAITFMessage(buf);
	printf("flow info - nonce 1 [%d], nonce 2 [%d], message type [%d]\n", 
		receivedFlow->nonce1, receivedFlow->nonce2, receivedFlow->messageType);
	return receivedFlow;
}


//This function converts a flow to a char buffer, easy to send over network
char* writeFlowStructAsNetworkBuffer(Flow* flow) {
	int in_addrSize = sizeof(struct in_addr);
	int intSize = sizeof(int);

	char* flowString = (char*)calloc(1, MAX_FLOW_SIZE);

	if(flow != NULL){
		memcpy(flowString, flow->attackerIP, in_addrSize);
		memcpy(flowString + in_addrSize, flow->victimIP, in_addrSize);
		memcpy(flowString + 2 * in_addrSize, &(flow->nonce1), intSize);
		memcpy(flowString + 2 * in_addrSize + intSize, &(flow->nonce2), intSize);
		memcpy(flowString + 2 * in_addrSize + 2 * intSize, &(flow->messageType), intSize);
		char* rrString = writeRouteRecordAsNetworkBuffer(flow->routeRecord);
		memcpy(flowString + 2 * in_addrSize + 3 * intSize, rrString, MAX_RR_HEADER_SIZE); 
	}
	return flowString;

}

//This function converts char array to the flow struct
Flow* readAITFMessage(char* flowInfo){

	int intSize = sizeof(int);
	Flow* flow = (Flow*)malloc(sizeof(Flow));

	//copy two addresses
	struct in_addr* rcvdAttackerIP = (struct in_addr*)malloc(sizeof(struct in_addr));
	struct in_addr* rcvdVictimIP = (struct in_addr*)malloc(sizeof(struct in_addr));
	memcpy(rcvdAttackerIP, flowInfo, intSize);
	memcpy(rcvdVictimIP, flowInfo + intSize, intSize);
	flow->attackerIP = rcvdAttackerIP;
	flow->victimIP = rcvdVictimIP;


	//copy nonce values and message type
	memcpy(&(flow->nonce1), flowInfo + 2 * intSize, intSize);
	memcpy(&(flow->nonce2), flowInfo + 3 * intSize, intSize);
	memcpy(&(flow->messageType), flowInfo + 4 * intSize, intSize);
	flow->routeRecord = readRouteRecord(flowInfo + 5 * intSize);

	return flow;

}


//This function converts the route record to a char buffer before sending it to network
char* writeRouteRecordAsNetworkBuffer(RouteRecord* routeRecord){
									

	int intSize = sizeof(int);
	int shortSize = sizeof(short);
	int longSize = sizeof(long);

	char* rrString = (char*)calloc(1, MAX_RR_HEADER_SIZE);

	if(routeRecord != NULL){

		memcpy(rrString, &(routeRecord->index), shortSize);
		memcpy(rrString + shortSize, &(routeRecord->size), shortSize);

		//the first slot should be guaranteed to have data
		memcpy(rrString + 2 * shortSize, (routeRecord->slot1)->ipAddress, intSize);
		memcpy(rrString + 2 * shortSize + intSize, &((routeRecord->slot1)->randomValue), longSize);

		if(routeRecord->slot2 != NULL){
			memcpy(rrString + 2 * shortSize + intSize + longSize, (routeRecord->slot2)->ipAddress, intSize);
			memcpy(rrString + 2 * shortSize + 2 * intSize + longSize, &((routeRecord->slot2)->randomValue), longSize);
		} else {
			memset(rrString + 2 * shortSize + intSize + longSize, '\0', intSize + longSize);
		}

		if(routeRecord->slot3 != NULL){
			memcpy(rrString + 2 * shortSize + 2 * intSize + 2 * longSize, (routeRecord->slot3)->ipAddress, intSize);
			memcpy(rrString + 2 * shortSize + 3 * intSize + 2 * longSize, &((routeRecord->slot3)->randomValue), longSize);
		} else {
			memset(rrString + 2 * shortSize + 2 * intSize + 2 * longSize, '\0', intSize + longSize);
		}

		if(routeRecord->slot4 != NULL){
			memcpy(rrString + 2 * shortSize + 3 * intSize + 3 * longSize, (routeRecord->slot4)->ipAddress, intSize);
			memcpy(rrString + 2 * shortSize + 4 * intSize + 3 * longSize, &((routeRecord->slot4)->randomValue), longSize);
		} else {
			memset(rrString + 2 * shortSize + 3 * intSize + 3 * longSize, '\0', intSize + longSize);

		}
	}


	return rrString;

}



RouteRecord* readRouteRecord(char* networkLayerPacketInfo){
	int intSize = sizeof(int);
	int shortSize = sizeof(short);
	int longSize = sizeof(long);

	RouteRecord* rr = (RouteRecord*)malloc(sizeof(RouteRecord));
	memcpy(&(rr->index), networkLayerPacketInfo, shortSize);
	memcpy(&(rr->size), networkLayerPacketInfo + shortSize, shortSize);

	RouteRecordSlot* slot1 = NULL;
	struct in_addr* slot1IPAddress = (struct in_addr*)malloc(sizeof(struct in_addr)); 
	memcpy(slot1IPAddress, networkLayerPacketInfo + 2 * shortSize, intSize);
	if(slot1IPAddress != NULL){
		slot1 = (RouteRecordSlot*)malloc(sizeof(RouteRecordSlot));
		slot1->ipAddress = slot1IPAddress;
		memcpy(&(slot1->randomValue), networkLayerPacketInfo + 2 * shortSize + intSize, longSize);
	}

	RouteRecordSlot* slot2 = NULL;
	struct in_addr* slot2IPAddress = (struct in_addr*)malloc(sizeof(struct in_addr)); 
	memcpy(slot2IPAddress, networkLayerPacketInfo + 2 * shortSize + ROUTE_RECORD_SLOT_SIZE, intSize);
	if(slot2IPAddress != NULL){
		slot2 = (RouteRecordSlot*)malloc(sizeof(RouteRecordSlot));
		slot2->ipAddress = slot2IPAddress;
		memcpy(&(slot2->randomValue), networkLayerPacketInfo + 2 * shortSize + ROUTE_RECORD_SLOT_SIZE + intSize, longSize);
	}

	RouteRecordSlot* slot3 = NULL;
	struct in_addr* slot3IPAddress = (struct in_addr*)malloc(sizeof(struct in_addr)); 	
	memcpy(slot3IPAddress, networkLayerPacketInfo + 2 * shortSize + 2 * ROUTE_RECORD_SLOT_SIZE, intSize);
	if(slot3IPAddress != NULL){
		slot3 = (RouteRecordSlot*)malloc(sizeof(RouteRecordSlot));
		slot3->ipAddress = slot3IPAddress;
		memcpy(&(slot3->randomValue), networkLayerPacketInfo + 2 * shortSize + 2 * ROUTE_RECORD_SLOT_SIZE + intSize, longSize);
	}

	RouteRecordSlot* slot4 = NULL;
	struct in_addr* slot4IPAddress = (struct in_addr*)malloc(sizeof(struct in_addr)); 	
	memcpy(slot4IPAddress, networkLayerPacketInfo + 2 * shortSize + 3 *ROUTE_RECORD_SLOT_SIZE, intSize);
	if(slot4IPAddress != NULL){
		slot4 = (RouteRecordSlot*)malloc(sizeof(RouteRecordSlot));
		slot4->ipAddress = slot3IPAddress;
		memcpy(&(slot4->randomValue), networkLayerPacketInfo + 2 * shortSize + 3 * ROUTE_RECORD_SLOT_SIZE + intSize, longSize);

	}

	rr->slot1 = slot1;
	rr->slot2 = slot2;
	rr->slot3 = slot3;
	rr->slot4 = slot4;

	return rr;
}

//initialize the AITF message list to point to null and the lock
void initializeAITFMessageList(){
	messageListPtr = NULL;
	lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
}



void reportError(char* errorMessage){
	printf("%s\n", errorMessage);
	exit(1);
}

pthread_t createAITFListeningThread(int port){
	pthread_t thread;
	//int listeningPortNumber = port;
	int* listeningPortNumber = calloc(1, sizeof(int));
	*(listeningPortNumber) = port;
	printf("Port Before: [%d]\n", port);
	if(pthread_create(&thread, NULL, listenToAITFMessage, listeningPortNumber) != 0){
		reportError("Error creating thread\n");
	}
	return thread;
}


void killThread(pthread_t thread){
	if(pthread_kill(thread, SIGINT)){
		reportError("Error killing thread\n");
	}
}

//Function ran by newly created thread to listen to incoming complaints
void* listenToAITFMessage(void *portNum){
	initializeAITFMessageList();
	int* portPtr = (int*) portNum;
	int port = *portPtr;
	printf("Port: [%d]\n", port);

	aitfListeningSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(aitfListeningSocket < 0){
		printf("Error in socket() when listening to AITF message.\n");
	}

	struct sockaddr_in addr;
	//bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;


	if(bind(aitfListeningSocket, (struct sockaddr*)&addr, sizeof(addr)) < 0){
		printf("Error in bind() when listening to AITF message. \n");
	}

	if(listen(aitfListeningSocket, 20) == -1){
		printf("Error in listen() when listening to AITF message. \n");
	}
	
	while(1){
		printf("enter loop for receiving packet\n");

		int clientfd;
		struct sockaddr_storage client_addr;
		int addrlen = sizeof(client_addr);
		clientfd = accept(aitfListeningSocket, (struct sockaddr*)&client_addr, (socklen_t * __restrict__)&addrlen);
	 	if(clientfd == -1) {
	 		printf("Error in accept() when listening to AITF message. \n");
	 	}

		Flow* receivedFlow = receiveFlowWithOpenConnection(clientfd);

	 	updateAITFMessageList(receivedFlow, clientfd);

	}

	return NULL;
}

//return the element that the message list pointer currently
//points to; return null if there is no new messages or the list
//is empty. 
AITFMessageListEntry* receiveAITFMessage(int* clientfd){
	//lock the AITF message list
	pthread_mutex_lock(&(lock));
	// printf("Start receiving AITF message\n");


	AITFMessageListEntry* returnedMessage = NULL;
	if(messageListPtr != NULL){
		returnedMessage = messageListPtr;
		messageListPtr = messageListPtr->next;
	}

	pthread_mutex_unlock(&(lock));
	// printf("Finish receiving AITF message\n");


	return returnedMessage;
	
}

//update AITF message list to add a new entry to its tail
void updateAITFMessageList(Flow* newAITFMessage, int clientfd){
	AITFMessageListEntry *newEntry = (AITFMessageListEntry *)malloc(sizeof(AITFMessageListEntry));
	newEntry->flow = newAITFMessage;
	newEntry->clientfd = clientfd;
	newEntry->next = NULL;

	pthread_mutex_lock(&(lock));
	printf("Start updating AITF message\n");

	if(messageListPtr == NULL){
		messageListPtr = newEntry;

	} else {
		AITFMessageListEntry *endPointer = messageListPtr;

		while(endPointer->next != NULL){
			endPointer = endPointer->next;
		}
		endPointer->next = newEntry;

	}

	pthread_mutex_unlock(&(lock));
	printf("Finish updating AITF message\n");

}


//This function frees memory of a flow struct
void freeFlow(Flow *flow) {
	free(flow->attackerIP);
	free(flow->victimIP);
	freeRouteRecord(flow->routeRecord);
	free(flow);
}

//This function frees memory of a RouteRecord struct
void freeRouteRecord(RouteRecord *rr){
	freeRouteRecordSlot(rr->slot1);
	freeRouteRecordSlot(rr->slot2);
	freeRouteRecordSlot(rr->slot3);
	freeRouteRecordSlot(rr->slot4);
	free(rr);
}

//This funciton fress memory of a RouteRecordSlot struct
void freeRouteRecordSlot(RouteRecordSlot *rrs){
	free(rrs->ipAddress);
	free(rrs);
}

//Code learned from http://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux
char* getIPAddress(char* interface){
	int fd;
	struct ifreq ifr;
	char* hostIP;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	hostIP = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

	printf("Host Interface (%s) Address: [%s]\n", interface, hostIP);
	return hostIP;
}

//This function converts ip address of char array type to the in_addr struct
struct in_addr* getInAddr(char* ipAddress){
	struct in_addr* tmpAddr = (struct in_addr*) calloc(1, sizeof(struct in_addr));
	inet_pton(AF_INET, ipAddress, tmpAddr);
	return tmpAddr;
}

//This function converts ip address of in_addr type to char array
char* convertIPAddress(struct in_addr* ipAddressStruct){
	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, ipAddressStruct, ip, INET_ADDRSTRLEN);
	return strdup(ip);
}


//To create nonce values, we will use a shared function that 
//will hash the source and destination IP into a new value; 
//we will XOR them together and XOR the result with a random 32-bit number. 
int createNonce(struct in_addr* sourceIP, struct in_addr* destIP){
	int value = (sourceIP->s_addr);
	value = value ^ (destIP->s_addr);
	value = value ^ createRandomInt();
	return value;
}

long createLongRandomValue(){
	long value = 0;
	long firstRand = ((long) createRandomInt()) << (sizeof(long) * 8 / 2);
	long secondRand = (long) createRandomInt();
	value = (long) firstRand;
	value = value | secondRand;
	printf("\nRandomValue: [%lu], [%lu], [%lu]\n\n", value, firstRand, secondRand);
	return value;
}

int isFirstNumber = TRUE;
int createRandomInt(){
	if(isFirstNumber == TRUE){
		isFirstNumber = FALSE;
		srand(time(NULL));
	}
	return rand();
}


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
	entry->count = 1;

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
//by comparing the source and dest IP address inside the flow. If it is not in the flow, it returns 0, otherwise
//it returns how many times it's been checked.
int isInShadowFilteringTable(Flow* flow){
	struct in_addr* attackerIP = flow->attackerIP;
	struct in_addr* victimIP = flow->victimIP;
	ShadowFilteringTableEntry *ptr = headTableEntry;
	int count = 0;

	pthread_mutex_lock(&(filteringTableLock));

	while(ptr != NULL){
		if(compareIPAddresses(attackerIP, (ptr->flow)->attackerIP) == 0 && 
			compareIPAddresses(victimIP, (ptr->flow)->victimIP) == 0){
			count = ptr->count;
			ptr->count = ptr->count + 1;
			break;
		}
		ptr = ptr->next;
	}

	pthread_mutex_unlock(&(filteringTableLock));

	return count;
}

//This function update the shadow filtering table by removing all entries that 
//are expired
void updateShadowFilteringTable(){
	struct timeval* currentTime = (struct timeval*)malloc(sizeof(struct timeval));
	gettimeofday(currentTime, NULL);

	pthread_mutex_lock(&(filteringTableLock));

	while(headTableEntry != NULL){
		if(hasTimeElapsed(headTableEntry->startTime, T_LONG) == TRUE) {
			//delete this entry
			ShadowFilteringTableEntry* toBeDeleted = headTableEntry;
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
	if(ip1 == NULL || ip2 == NULL)
	{
		if(ip1 == NULL && ip2 == NULL) return TRUE;
		return FALSE;
	}

	char ipStr1[INET_ADDRSTRLEN], ipStr2[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, ip1, ipStr1, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, ip2, ipStr2, INET_ADDRSTRLEN);
	return strcmp(ipStr1, ipStr2);
}




pthread_t startRouteRecordThread(){
	pthread_t thread;
	int arg = 0;
	if(pthread_create(&thread, NULL, routeRecordMain, &arg) != 0){
		reportError("Error creating route record thread\n");
	}
	waitMilliseconds(500);
	return thread;
}


int checkForCorrectRandomValue(char* ipAddress, long randomValue, Flow* receivedFlow){

	int correctRandomValue = FALSE;

	RouteRecord *receivedRR = receivedFlow->routeRecord;
	char ipStr[INET_ADDRSTRLEN];


	//get the slot that contains this gateway's ip address
	RouteRecordSlot *slot = NULL;
	if(receivedRR->slot1 != NULL){
		inet_ntop(AF_INET, (receivedRR->slot1)->ipAddress, ipStr, INET_ADDRSTRLEN);
		if(strcmp(ipAddress, ipStr) == 0){
			slot = receivedRR->slot1;
		} else if(receivedRR->slot2 != NULL){
			inet_ntop(AF_INET, (receivedRR->slot2)->ipAddress, ipStr, INET_ADDRSTRLEN);
			if(strcmp(ipAddress, ipStr) == 0){
				slot = receivedRR->slot2;
			} else if(receivedRR->slot3 != NULL){
				inet_ntop(AF_INET, (receivedRR->slot3)->ipAddress, ipStr, INET_ADDRSTRLEN);
				if(strcmp(ipAddress, ipStr) == 0){
					slot = receivedRR->slot3;
				} else if(receivedRR->slot4 != NULL){
					inet_ntop(AF_INET, (receivedRR->slot4)->ipAddress, ipStr, INET_ADDRSTRLEN);
					if(strcmp(ipAddress, ipStr) == 0){
						slot = receivedRR->slot4;
					}
				}
			}
		}
	}

	if(slot != NULL){
		if(randomValue == slot->randomValue){
			correctRandomValue = TRUE;
		}
	}

	return correctRandomValue;

}

/*char** addArgs = NULL;
char** deleteArgs = NULL;
char* anyAddrSource = NULL;
char* anyAddrDest = NULL;

//This function will manage blocking flows using iptables.
//source, can be null for any address, or set to the correct ip
//dest, can be null for any address, or set to the correct ip
//adding, defines if you want to remove a firewall rule (FALSE), or add one (TRUE)
void manageFlow(struct in_addr* source, struct in_addr* dest, int adding){
	if(addArgs == NULL){
		char** addArgs = (char**) calloc(20, sizeof(char*));
		addArgs[0] = strdup("/sbin/iptables");
		addArgs[1] = strdup("-I"); //Insert
		addArgs[2] = strdup("FORWARD");
		addArgs[3] = strdup("1");
		addArgs[4] = strdup("-s");
		addArgs[5] = strdup(""); //Source Address
		addArgs[6] = strdup("-d");
		addArgs[7] = strdup(""); //Dest Address
		addArgs[8] = strdup("-j");
		addArgs[9] = strdup("DROP"); //Action
		addArgs[10] = NULL; //End args
	}
	if(deleteArgs == NULL){
		char** deleteArgs = (char**) calloc(20, sizeof(char*));
		deleteArgs[0] = strdup("/sbin/iptables");
		deleteArgs[1] = strdup("-D"); //Delete
		deleteArgs[2] = strdup("FORWARD");
		deleteArgs[3] = strdup("-s");
		deleteArgs[4] = strdup(""); //Source Address
		deleteArgs[5] = strdup("-d");
		deleteArgs[6] = strdup(""); //Dest Address
		deleteArgs[7] = strdup("-j");
		deleteArgs[8] = strdup("DROP"); //Action
		deleteArgs[9] = NULL; //End args
	}
	if(anyAddrSource == NULL){
		anyAddrSource = strdup("0.0.0.0/0");
	}
	if(anyAddrDest == NULL){
		anyAddrDest = strdup("0.0.0.0/0");
	}

	char* sourceString = anyAddrSource;
	if(source != NULL){
		char ipStr[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, source, ipStr, INET_ADDRSTRLEN);
		sourceString = strdup(ipStr);
	}

	char* destString = anyAddrDest;
	if(dest != NULL){
		char ipStr[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, dest, ipStr, INET_ADDRSTRLEN);
		destString = strdup(ipStr);
	}

	char** args;
	if(adding == TRUE){
		args = addArgs;
		args[5] = sourceString;
		args[7] = destString;
	}
	else{
		args = deleteArgs;
		args[4] = sourceString;
		args[6] = destString;
	}

	int id = 0;
	if ((id = fork()) == 0) {
		execve(args[0], &args[0], 0);
		printf("Execve failed\n");
		exit(-1);
	}
	else {
		int status;
		waitpid(id, &status, 0);
		return;
	}
}*/

