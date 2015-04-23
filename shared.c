#include "shared.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
       
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>

#include <arpa/inet.h>

//This function lets the program sleep for the given milliseconds time
void wait(int millisecondsToWait){
	usleep(millisecondsToWait * 1000);

}

//This function checks if the time has elapsed, return 0 if the start time plus the given milliseconds
//is less than the current time
int hasTimeElapsed(struct timeval* startTime, int milliseconds){
	struct timeval currentTime;
	gettimeofday(&currentTime, NULL);
	double currentTimeInMill = currentTime.tv_sec * 1000 + (currentTime.tv_usec) / 1000;
	double expectedTime = startTime->tv_sec * 1000 + (startTime->tv_usec) / 1000 + milliseconds;
	//return 1 if the time has passed, otherwise return 0
	int returnVal = (currentTimeInMill - expectedTime > 0) ? 1 : 0;
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

	if(index < 2 || index > 4 || slotPointer == NULL || *slotPointer != NULL){
		//throw exception - not sure TODO
		printf("Error with routeRecord\n");
		exit(1);
	}

	*slotPointer = rrSlot; 
	(routeRecord->index)++;

}


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


int sendFlowStruct(struct in_addr* destIP, Flow* flow){ //TODO
	return 0;
}

//This function is used to send flow struct over the network  
int sendFlow(char* destIP, char* port, Flow* flow){
	// int sockfd;
	char* flowString = writeFlowStructAsNetworkBuffer(flow);
	printf("flow info - nonce 1, nonce 2, message type: %d, %d,%d\n", flow->nonce1, flow->nonce2, flow->messageType);
	Flow *tmp = readAITFMessage(flowString);
	printf("flow info - nonce 1, nonce 2, message type: %d, %d,%d\n", tmp->nonce1, tmp->nonce2, tmp->messageType);





	// char destIPChar[INET_ADDRSTRLEN];
	// struct addrinfo hints, *res;

	// hints.ai_family = AF_UNSPEC;
	// hints.ai_socktype = SOCK_STREAM;

	// //convert ip address to text
	// inet_ntop(AF_INET, &(destIP), destIPChar, INET_ADDRSTRLEN);

	// if(getaddrinfo(destIPChar, FLOW_SENDING_PORT, &hints, &res) != 0){ //TODO: DESTIPCHAR???
	// 	printf("getaddrinfo() failed\n");
	// 	exit(1);
	// }

	// // struct sockaddr_in destAddr;

	// // bzero(&destAddr, sizeof(destAddr));
	// // destAddr.sin_family = AF_INET;
	// // destAddr.sin_port = htons(FLOW_SENDING_PORT);
	// // destAddr.sin_addr.s_addr = destIP; //in_addr_t

	// sockfd = socket(AF_INET, SOCK_STREAM, 0); 
	// if(sockfd < 0) {
	// 	printf("socket() failed\n");
	// 	exit(1);
	// }

	// if(connect(sockfd, res->ai_addr, res->ai_addrlen) < 0){
	// 	printf("connect() failed.\n");
	// 	exit(1);
	// }

	// // int returnVal = sendto(sockfd, flowString, strlen(flowString), 0, 
	// // 	(struct sockaddr*)&destAddr, sizeof(destAddr);
	// 			//TODO not correct - stream->ignore address in sendto()
	// // return returnVal;


	// int returnVal = send(sockfd, flowString, strlen(flowString), 0);
	// return returnVal;

	//////////////////////////////
	int sockfd;
	struct addrinfo hints, *res;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	//hints.ai_flags = AI_PASSIVE;   //TODO comment out this line if source ip addr is given

	if(getaddrinfo(destIP, port, &hints, &res) != 0){ //TODO change null to ip address if source ip is given
		printf("Error in getaddrinfo() when sending complaint\n");
	}

	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if(sockfd < 0) printf("Error in socket() when sending complaint\n");

	// if(bind(sockfd, res->ai_addr, res->ai_addrlen) != 0){
	// 	printf("Error in bind() when sending complaint, %s\n", strerror(errno));
	// }

	if(connect(sockfd, res->ai_addr, res->ai_addrlen) != 0){
		printf("Error in connect() when sending complaint\n");
	}

	int returnval;

	if((returnval = send(sockfd, flowString, MAX_FLOW_SIZE, 0)) < 0){
		printf("Error occurred when sending request\n");
	} else {
		printf("Request sent\n");
		printf("length %d\n", returnval);
		printf("packet %s\n", flowString);
	}

	int optval = 1;
	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval)){
		printf("unable to let other processes to use the same socket: %s\n", strerror(errno));
	}

	if(close(sockfd) != 0){
		printf("close socket failed, error: %s\n", strerror(errno));

	}


	return returnval;

}


//This function converts a flow to a char buffer, easy to send over network
char* writeFlowStructAsNetworkBuffer(Flow* flow) {
	int in_addrSize = sizeof(struct in_addr);
	int intSize = sizeof(int);

	char* flowString = (char*)malloc(MAX_FLOW_SIZE);
	// bzero(&flowString, MAX_FLOW_SIZE);

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

	char* rrString = (char*)malloc(MAX_RR_HEADER_SIZE);
	// bzero(&rrString, MAX_RR_HEADER_SIZE);

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
			printf("slot2 null \n");
			memset(rrString + 2 * shortSize + intSize + longSize, '\0', intSize + longSize);
		}

		if(routeRecord->slot3 != NULL){
			memcpy(rrString + 2 * shortSize + 2 * intSize + 2 * longSize, (routeRecord->slot3)->ipAddress, intSize);
			memcpy(rrString + 2 * shortSize + 3 * intSize + 2 * longSize, &((routeRecord->slot3)->randomValue), longSize);

		} else {
			printf("slot3 null \n");
			memset(rrString + 2 * shortSize + 2 * intSize + 2 * longSize, '\0', intSize + longSize);

		}

		if(routeRecord->slot4 != NULL){
			memcpy(rrString + 2 * shortSize + 3 * intSize + 3 * longSize, (routeRecord->slot4)->ipAddress, intSize);
			memcpy(rrString + 2 * shortSize + 4 * intSize + 3 * longSize, &((routeRecord->slot4)->randomValue), longSize);
		} else {
			printf("slot4 null \n");
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

	RouteRecordSlot* slot1 = (RouteRecordSlot*)malloc(sizeof(RouteRecordSlot));
	struct in_addr* slot1IPAddress = (struct in_addr*)malloc(sizeof(struct in_addr)); 
	memcpy(slot1IPAddress, networkLayerPacketInfo + 2 * shortSize, intSize);
	slot1->ipAddress = slot1IPAddress;
	memcpy(&(slot1->randomValue), networkLayerPacketInfo + 2 * shortSize + intSize, longSize);

	RouteRecordSlot* slot2 = (RouteRecordSlot*)malloc(sizeof(RouteRecordSlot));
	struct in_addr* slot2IPAddress = (struct in_addr*)malloc(sizeof(struct in_addr)); 
	memcpy(slot2IPAddress, networkLayerPacketInfo + 2 * shortSize + ROUTE_RECORD_SLOT_SIZE, intSize);
	slot2->ipAddress = slot2IPAddress;
	memcpy(&(slot2->randomValue), networkLayerPacketInfo + 2 * shortSize + ROUTE_RECORD_SLOT_SIZE + intSize, longSize);

	RouteRecordSlot* slot3 = (RouteRecordSlot*)malloc(sizeof(RouteRecordSlot));
	struct in_addr* slot3IPAddress = (struct in_addr*)malloc(sizeof(struct in_addr)); 	
	memcpy(slot3IPAddress, networkLayerPacketInfo + 2 * shortSize + 2 * ROUTE_RECORD_SLOT_SIZE, intSize);
	slot3->ipAddress = slot3IPAddress;
	memcpy(&(slot3->randomValue), networkLayerPacketInfo + 2 * shortSize + 2 * ROUTE_RECORD_SLOT_SIZE + intSize, longSize);

	RouteRecordSlot* slot4 = (RouteRecordSlot*)malloc(sizeof(RouteRecordSlot));
	struct in_addr* slot4IPAddress = (struct in_addr*)malloc(sizeof(struct in_addr)); 	
	memcpy(slot4IPAddress, networkLayerPacketInfo + 2 * shortSize + 3 *ROUTE_RECORD_SLOT_SIZE, intSize);
	slot4->ipAddress = slot3IPAddress;
	memcpy(&(slot4->randomValue), networkLayerPacketInfo + 2 * shortSize + 3 * ROUTE_RECORD_SLOT_SIZE + intSize, longSize);

	rr->slot1 = slot1;
	rr->slot2 = slot2;
	rr->slot3 = slot3;
	rr->slot4 = slot4;

	return rr;
}

//initialize the AITF message list to point to null and the lock
void initializeAITFMessageList(){
	AITFMessageListHead = NULL;
	messageListPtr = AITFMessageListHead;
	lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
}

//TODO
//Function ran by newly created thread to listen to incoming complaints
void* listenToAITFMessage(void *portNum){
	initializeAITFMessageList();
	int sockfd;
	int port = *(int*)portNum;


	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0){
		printf("Error in socket() when listening to AITF message.\n");
	}

	struct sockaddr_in addr;
	//bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;//any address - not sure TODO


	if(bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0){
		printf("Error in bind() when listening to AITF message. \n");
	}

	if(listen(sockfd, 20) == -1){
		printf("Error in listen() when listening to AITF message. \n");
	}

	//fcntl(sockfd, F_SETFL, O_NONBLOCK); //make the socket non-block

	while(1){
		printf("enter loop for receiving packet\n");

		int clientfd;
		struct sockaddr_storage client_addr;
		int addrlen = sizeof(client_addr);
		clientfd = accept(sockfd, (struct sockaddr*)&client_addr, (socklen_t * __restrict__)&addrlen);
	 	if(clientfd == -1) {
	 		printf("Error in accept() when listening to AITF message. \n");
	 	} else {
	 		printf("accept() called\n");
	 	}

	 	char buf[2000];
	 	int count;
	 	memset(buf, 0, MAX_FLOW_SIZE + 10);
	 	count = recv(clientfd, buf, MAX_FLOW_SIZE, 0);
	 	buf[count] = '\0';
	 	printf("count number %d\n", count);
	 	printf("packet received. %s\n", buf);

	 	//handle AITF message
		Flow *receivedFlow = readAITFMessage(buf);
		printf("flow info - nonce 1, nonce 2, message type, string length: %d, %d,%d\n", 
			receivedFlow->nonce1, receivedFlow->nonce2, receivedFlow->messageType);

	 	//updateAITFMessageList(receivedFlow)


	 	//TODO - handle AITF

	}






	return NULL;
}

//return the next element that the message list pointer currently
//points to; return null if there is no new messages or the list
//is empty. 
//Also free memory of the messages that has already been handled. 
Flow* receiveAITFMessage(){
	//lock the AITF message list
	pthread_mutex_lock(&(lock));
	// printf("Start receiving AITF message\n");


	Flow* returnedMessage = NULL;
	if(messageListPtr != NULL && messageListPtr->next != NULL){
		messageListPtr = messageListPtr->next;
		returnedMessage = messageListPtr->flow;

		//and free the memory taken by messages that have already
		//been handled
		while(AITFMessageListHead != messageListPtr){
			Flow* tmp = AITFMessageListHead->flow;
			AITFMessageListHead = AITFMessageListHead->next;
			freeFlow(tmp);
		}
	}

	pthread_mutex_unlock(&(lock));
	// printf("Finish receiving AITF message\n");


	return returnedMessage;
	
}

//update AITF message list to add a new entry to its tail
void updateAITFMessageList(Flow* newAITFMessage){
	AITFMessageListEntry *newEntry = (AITFMessageListEntry *)malloc(sizeof(AITFMessageListEntry));
	newEntry->flow = newAITFMessage;
	newEntry->next = NULL;

	pthread_mutex_lock(&(lock));
	printf("Start updating AITF message\n");


	if(AITFMessageListHead == NULL){
		AITFMessageListHead = newEntry;
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

void freeFlow(Flow *flow) {
	free(flow->attackerIP);
	free(flow->victimIP);
	freeRouteRecord(flow->routeRecord);
	free(flow);
}

void freeRouteRecord(RouteRecord *rr){
	free(rr->slot1);
	free(rr->slot2);
	free(rr->slot3);
	free(rr->slot4);
	free(rr);
}





// int createNonce(int sourceIP, int destIP){
// 	//To create nonce values, we will use a shared function that 
// 	//will hash the source and destination IP into a new value; 
// 	//we will XOR them together and XOR the result with a random 32-bit number. 


// }

