#include "shared.h"
#include "attackerGateway.h"


extern int aitfListeningSocket;
pthread_t aitfListeningThread;
pthread_t routeRecordThread;

char* ownIPAddress;
long randomValue;

int isDisobedientGateway = FALSE;


void sigterm(int signum){
	int optval = 1;

	if(setsockopt(aitfListeningSocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval)){
		printf("unable to let other processes to use the same socket for listening AITF messages: %s\n", strerror(errno));
	}

	if(close(aitfListeningSocket) != 0){
		printf("close socket for listening AITF messages failed, error: %s\n", strerror(errno));

	}

	killThread(aitfListeningThread);
	killThread(routeRecordThread);
	printf("Exiting...\n");
	exit(1); 

}

//This function stop forwarding flow sending from attackerIP to victimIP
void* disconnectAttacker(struct in_addr* attackerIP, struct in_addr* victimIP){
	manageFlow(attackerIP, victimIP, TRUE);

	waitMilliseconds(T_LONG);
	manageFlow(attackerIP, victimIP, FALSE);

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
		disconnectAttacker(lastGatewayIP, flow->victimIP);
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
	manageFlow(ackFlow->attackerIP, ackFlow->victimIP, TRUE);
	printf("Temporary filter is set up for T-temp.\n");

	//send AITF message to attacker
	RouteRecord* RRToAttacker = createRouteRecord(getInAddr(ownIPAddress), randomValue);
	Flow* flowToAttacker = createFlowStruct(flow->victimIP, flow->attackerIP, RRToAttacker, nonce, 0, AITF_BLOCKING_REQUEST);
	int socketfd = sendFlow(convertIPAddress(flow->attackerIP), TCP_SENDING_PORT, flowToAttacker);
	close(socketfd);

	//Wait T-temp here
	waitMilliseconds(T_TEMP);
	
	//TODO check to see if the flow continues and disconnect A??
	//remove temporary filter after t-temp and add to shadow filtering table
	manageFlow(ackFlow->attackerIP, ackFlow->victimIP, FALSE);
	printf("Temporary filter removed. \n");
	addEntryToShadowFilteringTable(flow);

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

int main(int argc, char* argv[]){

	struct sigaction action;

	memset(&action, 0, sizeof (struct sigaction));
	action.sa_handler = sigterm;
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);

	//check for arguments
	if(argc == 2 && (strcmp(argv[1], "false") == 0 || strcmp(argv[1], "FALSE") == 0)){
		printf("Attacker gateway will respond to handshake but not block the flow.\n");
		isDisobedientGateway = TRUE;
	}

	struct timeval startTime;
	gettimeofday(&startTime, NULL);

	initializeShadowFilteringTableEntry();
	routeRecordThread = startRouteRecordThread();
	aitfListeningThread = createAITFListeningThread(TCP_RECEIVING_PORT);
	AITFMessageListEntry* receivedEntry = NULL;

	//get random value from route record thread
	randomValue = returnRandomValue();

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

				pthread_t thread;
				if(pthread_create(&thread, NULL, handleAITFMessage, receivedEntry) != 0){
					reportError("Error creating thread to handle AITF message\n");
				}

			} else {
				//send correct path to victim gateway
				printf("Random value associated with gateway is incorrect.\n");
				Flow* flow = receivedEntry->flow;
				flow->messageType = AITF_REQUEST_REPLY_NEW_PATH;

				sendFlowWithOpenConnection(receivedEntry->clientfd, flow);

			}
		}
		
		waitMilliseconds(100);

	}

	killThread(aitfListeningThread);
	killThread(routeRecordThread);

	return 0;
}