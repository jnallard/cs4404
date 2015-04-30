//shared.c  This is file is used to provide functions to all of our agents
//jnallard yyan

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

//This function will add a gateways info to the next available slot in a routerecord struct
void addGatewayInfo(RouteRecord* routeRecord, struct in_addr* ipAddress, long randomValue){

	//Create the new route record slot
	RouteRecordSlot *rrSlot = (RouteRecordSlot *)malloc(sizeof(RouteRecordSlot));
	rrSlot->ipAddress = ipAddress;
	rrSlot->randomValue = randomValue;

	//Find the next available slot
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

	//Assign the route record slot to the route record
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

	//Gets the information about the destination
	if(getaddrinfo(destIP, portStr, &hints, &res) != 0){ 
		printf("Error in getaddrinfo() when sending complaint\n");
		return -1;
	}

	//Open the socket
	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if(sockfd < 0) {
		printf("Error in socket() when sending complaint\n");
		return -1;
	}

	//Connect to the address
	if(connect(sockfd, res->ai_addr, res->ai_addrlen) != 0){
		printf("Error in connect() when sending complaint. Error: [%s]\n", strerror(errno));

		return -1;
	}

	//Once connected, you can send the flow
	sendFlowWithOpenConnection(sockfd, flow);

	return sockfd;

}

//Send a flow to a destination, using a socket that is already open.
int sendFlowWithOpenConnection(int connectionFd, Flow* flow){
	int returnval = 0;
	//Convert the flow to a string
	char* flowString = writeFlowStructAsNetworkBuffer(flow);

	//Send the string flow
	if((returnval = send(connectionFd, flowString, MAX_FLOW_SIZE, 0)) < 0){
		printf("Error occurred when sending request\n");
	} else {
		printf("Request sent\n");
	}

	//return the amount sent
	return returnval;
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

		//copy the index and size into the string
		memcpy(rrString, &(routeRecord->index), shortSize);
		memcpy(rrString + shortSize, &(routeRecord->size), shortSize);

		//the first slot should be guaranteed to have data
		memcpy(rrString + 2 * shortSize, (routeRecord->slot1)->ipAddress, intSize);
		memcpy(rrString + 2 * shortSize + intSize, &((routeRecord->slot1)->randomValue), longSize);

		//Copy the second slot into the string
		if(routeRecord->slot2 != NULL){
			memcpy(rrString + 2 * shortSize + intSize + longSize, (routeRecord->slot2)->ipAddress, intSize);
			memcpy(rrString + 2 * shortSize + 2 * intSize + longSize, &((routeRecord->slot2)->randomValue), longSize);
		} else {
			memset(rrString + 2 * shortSize + intSize + longSize, '\0', intSize + longSize);
		}

		//Copy the third
		if(routeRecord->slot3 != NULL){
			memcpy(rrString + 2 * shortSize + 2 * intSize + 2 * longSize, (routeRecord->slot3)->ipAddress, intSize);
			memcpy(rrString + 2 * shortSize + 3 * intSize + 2 * longSize, &((routeRecord->slot3)->randomValue), longSize);
		} else {
			memset(rrString + 2 * shortSize + 2 * intSize + 2 * longSize, '\0', intSize + longSize);
		}

		//Copy the fourth
		if(routeRecord->slot4 != NULL){
			memcpy(rrString + 2 * shortSize + 3 * intSize + 3 * longSize, (routeRecord->slot4)->ipAddress, intSize);
			memcpy(rrString + 2 * shortSize + 4 * intSize + 3 * longSize, &((routeRecord->slot4)->randomValue), longSize);
		} else {
			memset(rrString + 2 * shortSize + 3 * intSize + 3 * longSize, '\0', intSize + longSize);

		}
	}

	return rrString;
}

//Reads the string version of a route record back into a route record struct
RouteRecord* readRouteRecord(char* networkLayerPacketInfo){
	int intSize = sizeof(int);
	int shortSize = sizeof(short);
	int longSize = sizeof(long);

	//Read the index and size values
	RouteRecord* rr = (RouteRecord*)malloc(sizeof(RouteRecord));
	memcpy(&(rr->index), networkLayerPacketInfo, shortSize);
	memcpy(&(rr->size), networkLayerPacketInfo + shortSize, shortSize);

	//read the first slot
	RouteRecordSlot* slot1 = NULL;
	struct in_addr* slot1IPAddress = (struct in_addr*)malloc(sizeof(struct in_addr)); 
	memcpy(slot1IPAddress, networkLayerPacketInfo + 2 * shortSize, intSize);
	if(slot1IPAddress != NULL){
		slot1 = (RouteRecordSlot*)malloc(sizeof(RouteRecordSlot));
		slot1->ipAddress = slot1IPAddress;
		memcpy(&(slot1->randomValue), networkLayerPacketInfo + 2 * shortSize + intSize, longSize);
	}

	//read the second slot
	RouteRecordSlot* slot2 = NULL;
	struct in_addr* slot2IPAddress = (struct in_addr*)malloc(sizeof(struct in_addr)); 
	memcpy(slot2IPAddress, networkLayerPacketInfo + 2 * shortSize + ROUTE_RECORD_SLOT_SIZE, intSize);
	if(slot2IPAddress != NULL){
		slot2 = (RouteRecordSlot*)malloc(sizeof(RouteRecordSlot));
		slot2->ipAddress = slot2IPAddress;
		memcpy(&(slot2->randomValue), networkLayerPacketInfo + 2 * shortSize + ROUTE_RECORD_SLOT_SIZE + intSize, longSize);
	}

	//read the third slot
	RouteRecordSlot* slot3 = NULL;
	struct in_addr* slot3IPAddress = (struct in_addr*)malloc(sizeof(struct in_addr)); 	
	memcpy(slot3IPAddress, networkLayerPacketInfo + 2 * shortSize + 2 * ROUTE_RECORD_SLOT_SIZE, intSize);
	if(slot3IPAddress != NULL){
		slot3 = (RouteRecordSlot*)malloc(sizeof(RouteRecordSlot));
		slot3->ipAddress = slot3IPAddress;
		memcpy(&(slot3->randomValue), networkLayerPacketInfo + 2 * shortSize + 2 * ROUTE_RECORD_SLOT_SIZE + intSize, longSize);
	}

	//read the fourth slot
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

//Is used to print an error and then exit
void reportError(char* errorMessage){
	printf("%s\n", errorMessage);
	exit(1);
}

//Creates a thread that is used for listening to packets
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

//Function ran by newly created thread to listen to incoming complaints
void* listenToAITFMessage(void *portNum){
	//Creates the list for storing flows/aitf messages
	initializeAITFMessageList();

	//Gets the listening port number
	int* portPtr = (int*) portNum;
	int port = *portPtr;
	printf("Port: [%d]\n", port);

	//creates a listening socket
	aitfListeningSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(aitfListeningSocket < 0){
		printf("Error in socket() when listening to AITF message.\n");
	}

	struct sockaddr_in addr;
	//bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

	//Binds the socket
	if(bind(aitfListeningSocket, (struct sockaddr*)&addr, sizeof(addr)) < 0){
		printf("Error in bind() when listening to AITF message. \n");
	}

	//Starts the listening on this socket
	if(listen(aitfListeningSocket, 20) == -1){
		printf("Error in listen() when listening to AITF message. \n");
	}
	
	while(1){
		printf("enter loop for receiving packets\n");


		int clientfd;
		struct in_addr client_addr;
		int addrlen = sizeof(client_addr);

		///Accept a new connection as it comes in, storing the client's address
		clientfd = accept(aitfListeningSocket, (struct sockaddr*)&client_addr, (socklen_t * __restrict__)&addrlen);
	 	if(clientfd == -1) {
	 		printf("Error in accept() when listening to AITF message. \n");
	 	}
	 	
	 	//Read the flow from the connection
		Flow* receivedFlow = receiveFlowWithOpenConnection(clientfd);

		//We can add the flow as long as the client and the victim matching, given that it is a victim complaining about a flow
		if(compareIPAddresses(&client_addr, receivedFlow->victimIP) == 0  || receivedFlow->messageType != AITF_BLOCKING_REQUEST_VICTIM){
			updateAITFMessageList(receivedFlow, clientfd);

		} else {
			printf("Spoofed IP address in flow record. \n");
			
		}

	}

	return NULL;
}

//return the element that the message list pointer currently
//points to; return null if there is no new messages or the list
//is empty. 
AITFMessageListEntry* receiveAITFMessage(int* clientfd){
	//lock the AITF message list
	pthread_mutex_lock(&(lock));

	//Return the first AITF message in the list
	AITFMessageListEntry* returnedMessage = NULL;
	if(messageListPtr != NULL){
		returnedMessage = messageListPtr;
		messageListPtr = messageListPtr->next;
	}

	pthread_mutex_unlock(&(lock));

	return returnedMessage;
	
}

//Receives a flow from a connection that has already been opened
Flow* receiveFlowWithOpenConnection(int connectionFd){

 	char buf[2000];
 	int count;
 	memset(buf, 0, MAX_FLOW_SIZE + 10);

 	//Receive the flow
 	count = recv(connectionFd, buf, MAX_FLOW_SIZE, 0);

 	//Nothing Received
 	if(count == 0){
 		return NULL;
 	}

 	buf[count] = '\0';
 	printf("count number %d\n", count);
 	printf("packet received.\n");

 	//Read the buffer as a flow struct
	Flow *receivedFlow = readAITFMessage(buf);
	printf("flow info - nonce 1 [%d], nonce 2 [%d], message type [%d]\n", 
		receivedFlow->nonce1, receivedFlow->nonce2, receivedFlow->messageType);
	return receivedFlow;
}

//update AITF message list to add a new entry to its tail
void updateAITFMessageList(Flow* newAITFMessage, int clientfd){

	//Create the new list entry
	AITFMessageListEntry *newEntry = (AITFMessageListEntry *)malloc(sizeof(AITFMessageListEntry));
	newEntry->flow = newAITFMessage;
	newEntry->clientfd = clientfd;
	newEntry->next = NULL;

	pthread_mutex_lock(&(lock));
	printf("Start updating AITF message\n");

	//Appy it as the first if it's null
	if(messageListPtr == NULL){
		messageListPtr = newEntry;

	} else {
		//Otherwise, add it ot the end of the list
		AITFMessageListEntry *endPointer = messageListPtr;

		while(endPointer->next != NULL){
			endPointer = endPointer->next;
		}
		endPointer->next = newEntry;

	}

	pthread_mutex_unlock(&(lock));
	printf("Finish updating AITF message\n");

}

//Code learned from http://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux
//Gets the ip address of an interface
char* getIPAddress(char* interface){
	int fd;
	struct ifreq ifr;
	char* hostIP;

	//Create a socket, and use that to get the interface's name.
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

//Creates to random ints, and places them side by side to create a long random value
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

//This function creates a random int, and uses the isFirstNumber to set srand
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

	//Get the current time
	struct timeval* currentTime = (struct timeval*)malloc(sizeof(struct timeval));
	gettimeofday(currentTime, NULL);

	//Set the values
	entry->flow = flow;
	entry->startTime = currentTime;
	entry->next = NULL;
	entry->count = 1;

	pthread_mutex_lock(&(filteringTableLock));

	if(headTableEntry == NULL){
		//Add it as the head of the list if empty
		headTableEntry = entry;
	} else {
		//Otherwise, store it at the end
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

	//FInd the flow with matching ip addresses
	while(ptr != NULL){
		if(compareIPAddresses(attackerIP, (ptr->flow)->attackerIP) == 0 && 
			compareIPAddresses(victimIP, (ptr->flow)->victimIP) == 0){
			count = ptr->count;
			//increment the count if found
			ptr->count = ptr->count + 1;
			break;
		}
		ptr = ptr->next;
	}

	pthread_mutex_unlock(&(filteringTableLock));

	//rturn the count, zero if not found
	return count;
}

//This function update the shadow filtering table by removing all entries that 
//are expired
void updateShadowFilteringTable(){

	pthread_mutex_lock(&(filteringTableLock));

	while(headTableEntry != NULL){
		if(hasTimeElapsed(headTableEntry->startTime, T_LONG) == TRUE) {
			//if the time has elapsed from the entries addition, delete this entry
			ShadowFilteringTableEntry* toBeDeleted = headTableEntry;
			headTableEntry = headTableEntry->next;

			freeFlow(toBeDeleted->flow);
			free(toBeDeleted->startTime);
			free(toBeDeleted);

		} else break;
		//Since we add to this list in order of time, we can stop once we find one that's not expired
	}

	pthread_mutex_unlock(&(filteringTableLock));

}


//This function compares two ip addresses to see if they are the same, and return 0 if they are.
int compareIPAddresses(struct in_addr* ip1, struct in_addr* ip2){
	//If an address is set to null, only return true if they are both null
	if(ip1 == NULL || ip2 == NULL)
	{
		if(ip1 == NULL && ip2 == NULL) return TRUE;
		return FALSE;
	}

	//Otherwise, compare the strings and return the result
	char ipStr1[INET_ADDRSTRLEN], ipStr2[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, ip1, ipStr1, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, ip2, ipStr2, INET_ADDRSTRLEN);
	return strcmp(ipStr1, ipStr2);
}

//Starts the thread for inserting route records into packets going through a gateway
pthread_t startRouteRecordThread(){
	pthread_t thread;
	int arg = 0;
	if(pthread_create(&thread, NULL, routeRecordMain, &arg) != 0){
		reportError("Error creating route record thread\n");
	}
	waitMilliseconds(500);
	return thread;
}

//Checks all of the slots for one matching the given ip address, and if it finds it, will return the comparison
//of the randomvalue in the slot with the one for the actual gateway
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

	//If a slot was found, check the random values
	if(slot != NULL){
		if(randomValue == slot->randomValue){
			correctRandomValue = TRUE;
		}
	}

	return correctRandomValue;

}


//Kills a thread - Murder is sad.
void killThread(pthread_t thread){
	if(pthread_kill(thread, SIGINT)){
		reportError("Error killing thread\n");
	}
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

