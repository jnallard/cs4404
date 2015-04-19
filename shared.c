#include "shared.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
       
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

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
RouteRecord* createRouteRecord(int ipAddress, long randomValue){
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


void addGatewayInfo(RouteRecord* routeRecord, int ipAddress, long randomValue){
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

//This function is used to send flow struct over the network    TODO unsure
int sendFlowStruct(struct in_addr* destIP, struct Flow* flow){
	int sockfd;
	char* flowString = writeFlowStructAsNetworkBuffer(flow);

	char destIPChar[INET_ADDRSTRLEN];
	struct addrinfo hints, *res;

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	//convert ip address to text
	inet_ntop(AF_INET, &(destIP), destIPChar, INET_ADDRSTRLEN);

	if(getaddrinfo(destIPChar, FLOW_SENDING_PORT, &hints, &res) != 0){ //TODO: DESTIPCHAR???
		printf("getaddrinfo() failed\n");
		exit(1);
	}

	// struct sockaddr_in destAddr;

	// bzero(&destAddr, sizeof(destAddr));
	// destAddr.sin_family = AF_INET;
	// destAddr.sin_port = htons(FLOW_SENDING_PORT);
	// destAddr.sin_addr.s_addr = destIP; //in_addr_t

	sockfd = socket(AF_INET, SOCK_STREAM, 0); 
	if(sockfd < 0) {
		printf("socket() failed\n");
		exit(1);
	}

	if(connect(sockfd, res->ai_addr, res->ai_addrlen) < 0){
		printf("connect() failed.\n");
		exit(1);
	}

	// int returnVal = sendto(sockfd, flowString, strlen(flowString), 0, 
	// 	(struct sockaddr*)&destAddr, sizeof(destAddr);
				//TODO not correct - stream->ignore address in sendto()
	// return returnVal;


	int returnVal = send(sockfd, flowString, strlen(flowString), 0);
	return returnVal;



}


//This function converts a flow to a char buffer, easy to send over network
char* writeFlowStructAsNetworkBuffer(Flow* flow) {
	int in_addrSize = sizeof(struct in_addr);
	int intSize = sizeof(int);

	char* flowString = (char*)malloc(MAX_FLOW_SIZE);

	memcpy(flowString, flow->attackerIP, in_addrSize);
	memcpy(flowString + in_addrSize, flow->victimIP, in_addrSize);
	memcpy(flowString + 2 * in_addrSize, &(flow->nonce1), intSize);
	memcpy(flowString + 2 * in_addrSize + intSize, &(flow->nonce2), intSize);
	memcpy(flowString + 2 * in_addrSize + 2 * intSize, &(flow->messageType), intSize);

	char* rrString = writeRouteRecordAsNetworkBuffer(flow->routeRecord);
	memcpy(flowString + 2 * in_addrSize + 3 * intSize, rrString, MAX_RR_HEADER_SIZE); 

	return flowString;

}

//This function converts the route record to a char buffer before sending it to network
char* writeRouteRecordAsNetworkBuffer(RouteRecord* routeRecord){

	int intSize = sizeof(int);
	int shortSize = sizeof(short);
	int longSize = sizeof(long);

	char* rrString = (char*)malloc(MAX_RR_HEADER_SIZE);

	memcpy(rrString, &(routeRecord->index), shortSize);
	memcpy(rrString + shortSize, &(routeRecord->size), shortSize);

	memcpy(rrString + 2 * shortSize, &((routeRecord->slot1)->ipAddress), intSize);
	memcpy(rrString + 2 * shortSize + intSize, &((routeRecord->slot1)->randomValue), longSize);

	memcpy(rrString + 2 * shortSize + intSize + longSize, &((routeRecord->slot1)->ipAddress), intSize);
	memcpy(rrString + 2 * shortSize + 2 * intSize + longSize, &((routeRecord->slot1)->randomValue), longSize);

	memcpy(rrString + 2 * shortSize + 2 * intSize + 2 * longSize, &((routeRecord->slot1)->ipAddress), intSize);
	memcpy(rrString + 2 * shortSize + 3 * intSize + 2 * longSize, &((routeRecord->slot1)->randomValue), longSize);

	memcpy(rrString + 2 * shortSize + 3 * intSize + 3 * longSize, &((routeRecord->slot1)->ipAddress), intSize);
	memcpy(rrString + 2 * shortSize + 4 * intSize + 3 * longSize, &((routeRecord->slot1)->randomValue), longSize);

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
	memcpy(&(slot1->ipAddress), networkLayerPacketInfo + 2 * shortSize, intSize);
	memcpy(&(slot1->randomValue), networkLayerPacketInfo + 2 * shortSize + intSize, longSize);

	RouteRecordSlot* slot2 = (RouteRecordSlot*)malloc(sizeof(RouteRecordSlot));
	memcpy(&(slot2->ipAddress), networkLayerPacketInfo + 2 * shortSize + ROUTE_RECORD_SLOT_SIZE, intSize);
	memcpy(&(slot2->randomValue), networkLayerPacketInfo + 2 * shortSize + ROUTE_RECORD_SLOT_SIZE + intSize, longSize);

	RouteRecordSlot* slot3 = (RouteRecordSlot*)malloc(sizeof(RouteRecordSlot));
	memcpy(&(slot3->ipAddress), networkLayerPacketInfo + 2 * shortSize + 2 * ROUTE_RECORD_SLOT_SIZE, intSize);
	memcpy(&(slot3->randomValue), networkLayerPacketInfo + 2 * shortSize + 2 * ROUTE_RECORD_SLOT_SIZE + intSize, longSize);

	RouteRecordSlot* slot4 = (RouteRecordSlot*)malloc(sizeof(RouteRecordSlot));
	memcpy(&(slot4->ipAddress), networkLayerPacketInfo + 2 * shortSize + 3 *ROUTE_RECORD_SLOT_SIZE, intSize);
	memcpy(&(slot4->randomValue), networkLayerPacketInfo + 2 * shortSize + 3 * ROUTE_RECORD_SLOT_SIZE + intSize, longSize);

	rr->slot1 = slot1;
	rr->slot2 = slot2;
	rr->slot3 = slot3;
	rr->slot4 = slot4;

	return rr;
}


// int createNonce(int sourceIP, int destIP){
// 	//To create nonce values, we will use a shared function that 
// 	//will hash the source and destination IP into a new value; 
// 	//we will XOR them together and XOR the result with a random 32-bit number. 


// }

