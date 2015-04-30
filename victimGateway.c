#include "shared.h"

pthread_t startHandleFlowThread(Flow* flow);
void* handleFlow(void* flowPtr);
void requestFlowBlocked(Flow* flow);
void escalateFlow(Flow* flow);

extern int aitfListeningSocket;
pthread_t aitfListeningThread;
pthread_t routeRecordThread;
struct in_addr* thisGatewayIP = NULL;

void sigterm(int signum){

	killThread(aitfListeningThread);
	killThread(routeRecordThread);

	int optval = 1;

	if(setsockopt(aitfListeningSocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval)){
		printf("unable to let other processes to use the same socket for listening AITF messages: %s\n", strerror(errno));
	}

	if(close(aitfListeningSocket) != 0){
		printf("close socket for listening AITF messages failed, error: %s\n", strerror(errno));

	}
	printf("Exiting...\n");
	exit(1); 

}

int main(int argc, char* argv[]){
	char* ipString = getIPAddress(INTERFACE);
	thisGatewayIP = getInAddr(ipString);

	struct sigaction action;

	memset(&action, 0, sizeof (struct sigaction));
	action.sa_handler = sigterm;
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);

	int running = TRUE;
	struct timeval startTime;
	gettimeofday(&startTime, NULL);

	void initializeShadowFilteringTableEntry();
	routeRecordThread = startRouteRecordThread();
	aitfListeningThread = createAITFListeningThread(TCP_RECEIVING_PORT);

	while(running == TRUE){

		if(hasTimeElapsed(&startTime, T_TABLE_CHECK) == TRUE){
			gettimeofday(&startTime, NULL);
			updateShadowFilteringTable();

		}
		AITFMessageListEntry* entry = receiveAITFMessage(); 

		if(entry != NULL){
			Flow* flow = entry->flow;
			startHandleFlowThread(flow);
		}
		waitMilliseconds(100);

	}

	killThread(aitfListeningThread);
	killThread(routeRecordThread);
	return 0;
}

pthread_t startHandleFlowThread(Flow* flow){
	pthread_t thread;
	if(pthread_create(&thread, NULL, handleFlow, (void*) flow) != 0){
		reportError("Error creating flow handling thread\n");
	}
	return thread;
}

void* handleFlow(void* flowPtr){

	Flow* flow = (Flow*) flowPtr;

	long randomValue = returnRandomValue();
	char* ownIPAddress = getIPAddress(INTERFACE);

	if(checkForCorrectRandomValue(ownIPAddress, randomValue, flow) == TRUE){
		printf("The random value does not match for this gateway.\n");
		pthread_exit(NULL);
	}

	//Gets the number of times we've seen the flow.
	int count = isInShadowFilteringTable(flow);
	if(count <= 1){
		//contact Attack Gateway
		requestFlowBlocked(flow);
	}
	else{
		//Escalate against the Attacker Gateway
		escalateFlow(flow);
	}

	pthread_exit(NULL);
}

void requestFlowBlocked(Flow* flow){
	struct timeval startTime;
	gettimeofday(&startTime, NULL);

	//Block the flow temporarily
	//manageFlow(flow->attackerIP, flow->victimIP, TRUE);
	addBlockedFlow(flow->attackerIP, flow->victimIP, T_TEMP);

	flow->messageType = AITF_BLOCKING_REQUEST;
	flow->nonce2 = createNonce(flow->attackerIP, flow->victimIP);
	char* attackerGatewayIP = convertIPAddress(flow->routeRecord->slot1->ipAddress);

	int connectionFd = sendFlow(attackerGatewayIP, TCP_RECEIVING_PORT, flow);
	Flow* responseFlow = receiveFlowWithOpenConnection(connectionFd);

	//The attacker gateway did not respond
	if(responseFlow == NULL){
		escalateFlow(flow);
		return;
	}

	//If the path we had wasn't right, or if we detected someone tampering with our messages, we will just block locally
	if(responseFlow->messageType != AITF_REQUEST_REPLY || flow->nonce2 != responseFlow->nonce2){
		waitMilliseconds(T_LONG);
		//manageFlow(flow->attackerIP, flow->victimIP, FALSE);
		removeBlockedFlowAndCountViolations(flow->attackerIP, flow->victimIP);
		return;
	}

	//Everything else seems to be working up to this point, so respond to the messages
	responseFlow->messageType = AITF_REPLY_ACKNOWLEDGEMENT;
	sendFlowWithOpenConnection(connectionFd, responseFlow);
	close(connectionFd);

	addEntryToShadowFilteringTable(flow);

	while(hasTimeElapsed(&startTime, T_TEMP) == FALSE){
		waitMilliseconds(T_TEMP / 10);
	}
	//manageFlow(flow->attackerIP, flow->victimIP, FALSE);
	printf("About to remove flow\n");
	removeBlockedFlowAndCountViolations(flow->attackerIP, flow->victimIP);
		

}

void escalateFlow(Flow* flow){

	flow->messageType = AITF_ESCALATION_REQUEST;
	RouteRecord* rr = flow->routeRecord;
	RouteRecordSlot* slot = rr->slot2;

	//If there is no information or I'm the next available gateway, block locally.
	if(slot == NULL || (slot->ipAddress != NULL && compareIPAddresses(slot->ipAddress, thisGatewayIP) == TRUE)){
		//manageFlow(NULL, flow->victimIP, TRUE);
		addBlockedFlow(flow->attackerIP, flow->victimIP, T_LONG);
	}
	else{
		//Otherwise, contact the gateway closest to the Attack Gateway
		char* nextGatewayIP = convertIPAddress(slot->ipAddress);
		sendFlow(nextGatewayIP, TCP_RECEIVING_PORT, flow);
	}
}