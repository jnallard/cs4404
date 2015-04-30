//attackerGateway.c  This is file is used to represent the attackerGateway in our system, 
//who will receive block messages from the victim gateway, and respond to the or not,
//depending upon if it is malicious or not
//jnallard yyan

#include "shared.h"

extern int aitfListeningSocket;
pthread_t aitfListeningThread;
pthread_t routeRecordThread;

char* ownIPAddress;
long randomValue;

//The value used for determining the maliciousness of this gatewat
int isDisobedientGateway = FALSE;

//prototypes for the functions
void sigterm(int signum);
void* disconnectAttacker(struct in_addr* attackerIP, struct in_addr* victimIP);
void handleEscalationRequest(AITFMessageListEntry* receivedEntry);
void handleAITFHandshake(AITFMessageListEntry *entry);
void* handleAITFMessage(void *tableEntry);

//This is the main function for starting the gateway and doing its respective actions
int main(int argc, char* argv[]){

	//Create the function to be handled when a control exit command is detected
	struct sigaction action;
	memset(&action, 0, sizeof (struct sigaction));
	action.sa_handler = sigterm;
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);

	//This determines if the gateway will be malicious or not
	if(argc == 2 && (strcmp(argv[1], "false") == 0 || strcmp(argv[1], "FALSE") == 0)){
		printf("Attacker gateway will respond to handshake but not block the flow.\n");
		isDisobedientGateway = TRUE;
	}

	//Get the start time
	struct timeval startTime;
	gettimeofday(&startTime, NULL);

	//Create the threads necessary for listening, packet manipulation, and shadow filtering
	initializeShadowFilteringTableEntry();
	routeRecordThread = startRouteRecordThread();
	aitfListeningThread = createAITFListeningThread(TCP_RECEIVING_PORT);
	AITFMessageListEntry* receivedEntry = NULL;

	//get random value from route record thread
	randomValue = returnRandomValue();

	//Get the ip address of the gateway
	ownIPAddress = getIPAddress(INTERFACE);

	while(1){
		//update shadow filtering table
		if(hasTimeElapsed(&startTime, T_TABLE_CHECK)){
			gettimeofday(&startTime, NULL);
			updateShadowFilteringTable();
		}
		if((receivedEntry = receiveAITFMessage()) != NULL){
			//check if flow contains correct R number
			if(checkForCorrectRandomValue(ownIPAddress, randomValue, receivedEntry->flow) == TRUE){

				//If the flow is good, create a thread to handle it
				pthread_t thread;
				if(pthread_create(&thread, NULL, handleAITFMessage, receivedEntry) != 0){
					reportError("Error creating thread to handle AITF message\n");
				}

			} else {
				//send correct path to victim gateway (We don't actually specify one, since the victim gateway will just 
				// choose to block the flow locally.)
				printf("Random value associated with gateway is incorrect.\n");
				Flow* flow = receivedEntry->flow;
				flow->messageType = AITF_REQUEST_REPLY_NEW_PATH;
				sendFlowWithOpenConnection(receivedEntry->clientfd, flow);
			}
		}
		
		waitMilliseconds(100);

	}

	//Kill the threads being used
	killThread(aitfListeningThread);
	killThread(routeRecordThread);

	return 0;
}

//This function will handle what happens when a control command is given to exit
void sigterm(int signum){

	//Kill the threads being used
	killThread(aitfListeningThread);
	killThread(routeRecordThread);

	int optval = 1;

	//Try to free the port for reuse
	if(setsockopt(aitfListeningSocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval)){
		printf("unable to let other processes to use the same socket for listening AITF messages: %s\n", strerror(errno));
	}

	//Close the socket
	if(close(aitfListeningSocket) != 0){
		printf("close socket for listening AITF messages failed, error: %s\n", strerror(errno));

	}
	printf("Exiting...\n");
	exit(1); 

}

//This function stop forwarding flow sending from attackerIP to victimIP
void* disconnectAttacker(struct in_addr* attackerIP, struct in_addr* victimIP){

	//Will have the route record system block flows
	addBlockedFlow(attackerIP, victimIP, T_LONG);

	pthread_exit(NULL);
}

//This function handles escalation request by stopping the flow sending from 
//the last gateway to the given victim IP address
void handleEscalationRequest(AITFMessageListEntry* receivedEntry){
	
	Flow* flow = receivedEntry->flow;
	RouteRecord *rr = flow->routeRecord;
	struct in_addr* ipAddress = getInAddr(ownIPAddress);

	//find out the ip address of the compromised gateway
	struct in_addr* lastGatewayIP = NULL;
	if(rr->slot2 != NULL && compareIPAddresses((rr->slot2)->ipAddress, ipAddress) == 0){
		lastGatewayIP = (rr->slot1)->ipAddress;
	} else if(rr->slot3 != NULL && compareIPAddresses((rr->slot3)->ipAddress, ipAddress) == 0){
		lastGatewayIP = (rr->slot2)->ipAddress;
	} else if(rr->slot4 != NULL && compareIPAddresses((rr->slot4)->ipAddress, ipAddress) == 0){
		lastGatewayIP = (rr->slot3)->ipAddress;
	}

	if(lastGatewayIP == NULL){
		printf("Error: cannot find the last gateway's ip in escalation.\n");
	} else {
		//Since we are using a linear network (only one path) we can protect a client by blocking 
		//all upstream traffic to it, since that would be the equivalent as blocking packets from the
		//next router
		disconnectAttacker(NULL, flow->victimIP);
		printf("Escalation: block flow from %s\n", convertIPAddress(lastGatewayIP));
	}

}

//This function responds to AITF handshake request.
//It will also set up the filter and manage the flow if the gateway is obedient.
void handleAITFHandshake(AITFMessageListEntry *entry){
	Flow* flow = entry->flow;
	int clientfd = entry->clientfd;

	//modify the packet to include nonce 1 and renewed message type
	int nonce = createNonce(flow->attackerIP, flow->victimIP);
	flow->nonce1 = nonce;
	flow->messageType = AITF_REQUEST_REPLY;

	//send the packet back to the victim using clientfd
	sendFlowWithOpenConnection(clientfd, flow);

	//waiting for the reply acknowledgement
	Flow *ackFlow = receiveFlowWithOpenConnection(clientfd);

	close(clientfd);
	//check if flow is null and its nonce value and if the message type is acknowledgement
	if(ackFlow == NULL || ackFlow->nonce1 != nonce || ackFlow->messageType != AITF_REPLY_ACKNOWLEDGEMENT){
		//if nonce value not correct, thread finishes
		if(ackFlow == NULL) printf("Didn't receive acknowledgement in handshake, thread exits.\n");
		else if(ackFlow->nonce1 != nonce) printf("Incorrect nonce1 value received, thread exits. \n");
		else if(ackFlow->messageType != AITF_REPLY_ACKNOWLEDGEMENT) printf("Ack message doesn't contain correct message type.\n");
		pthread_exit(NULL);
	}

	//if it's disobedient gateway, when handshake is complete, do not manage flow and exit
	if(isDisobedientGateway == TRUE){
		pthread_exit(NULL);		
	}

	//set up the temporary filter for t-temp
	//manageFlow(ackFlow->attackerIP, ackFlow->victimIP, TRUE);
	addBlockedFlow(ackFlow->attackerIP, ackFlow->victimIP, T_TEMP);
	printf("Temporary filter is set up for T-temp.\n");

	//send AITF message to attacker
	RouteRecord* RRToAttacker = createRouteRecord(getInAddr(ownIPAddress), randomValue);
	Flow* flowToAttacker = createFlowStruct(flow->victimIP, flow->attackerIP, RRToAttacker, nonce, 0, AITF_BLOCKING_REQUEST);
	int socketfd = sendFlow(convertIPAddress(flow->attackerIP), TCP_RECEIVING_PORT, flowToAttacker);
	close(socketfd);

	//Wait T-temp here
	waitMilliseconds(T_TEMP * 2);
	
	//remove temporary filter after t-temp
	int messageCountViolations = removeBlockedFlowAndCountViolations(ackFlow->attackerIP, ackFlow->victimIP);

	//If the flow disobeyed and kept attacking, block it. Otherwise put it in the shadow filtering table
	if(messageCountViolations > 0){
		disconnectAttacker(flow->attackerIP, NULL);
	} else {
		addEntryToShadowFilteringTable(flow);

	}


}

//This function handles AITF messages by checking its validity and type
void* handleAITFMessage(void *tableEntry){
	AITFMessageListEntry* receivedEntry = (AITFMessageListEntry*)tableEntry;
	//check to see if the flow is in shadow filtering table once	
	if(isInShadowFilteringTable(receivedEntry->flow) > 0){
		//disconnect Attacker
		disconnectAttacker((receivedEntry->flow)->attackerIP, NULL);

	} else if((receivedEntry->flow)->messageType == AITF_ESCALATION_REQUEST){
		//check if it's an escalation request
		printf("Handle escalation request.\n");
		handleEscalationRequest(receivedEntry);			

	} else if((receivedEntry->flow)->messageType != AITF_BLOCKING_REQUEST){
		//the first received AITF message type should be the blocking request
		printf("The AITF message type is not blocking request but type %d.\n", 
			(receivedEntry->flow)->messageType);

	} else {
		//use the client fd to further handle the handshake
		handleAITFHandshake(receivedEntry);

	}

	pthread_exit(NULL);

}
