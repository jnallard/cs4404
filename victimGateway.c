//Victim Gateway software - used for forwarding packets and handle complaints from the Victim
//jnallard, yyan

#include "shared.h"

pthread_t startHandleFlowThread(Flow* flow);
void* handleFlow(void* flowPtr);
void requestFlowBlocked(Flow* flow);
void escalateFlow(Flow* flow);
void sigterm(int signum);

extern int aitfListeningSocket;
pthread_t aitfListeningThread;
pthread_t routeRecordThread;
struct in_addr* thisGatewayIP = NULL;



int main(int argc, char* argv[]){
	//Get the IP address of this host
	char* ipString = getIPAddress(INTERFACE);
	thisGatewayIP = getInAddr(ipString);

	//Setup function to handle SIGINT and SIGTERM
	struct sigaction action;
	memset(&action, 0, sizeof (struct sigaction));
	action.sa_handler = sigterm;
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);

	//Initialize fields, start timer
	int running = TRUE;
	struct timeval startTime;
	gettimeofday(&startTime, NULL);

	//Initialize shadow filtering table and start threads for listening to AITF message
	//and route record to modify packets before forwarding
	void initializeShadowFilteringTableEntry();
	routeRecordThread = startRouteRecordThread();
	aitfListeningThread = createAITFListeningThread(TCP_RECEIVING_PORT);

	while(running == TRUE){
		//If the time for checking shadow filtering table has passed, update the table
		if(hasTimeElapsed(&startTime, T_TABLE_CHECK) == TRUE){
			gettimeofday(&startTime, NULL);
			updateShadowFilteringTable();

		}

		//Receive AITF message, if any
		AITFMessageListEntry* entry = receiveAITFMessage(); 

		//If AITF message received, handle it in a new thread
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

//This function is used to properly handle SIGINT and SIGTERM signals to stop the process
void sigterm(int signum){

	//Kill the listening and packets forwarding threads
	killThread(aitfListeningThread);
	killThread(routeRecordThread);

	int optval = 1;

	//Allow the socket to be used by the other process
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

//This function is used to create a new thread to handle incoming flow struct
pthread_t startHandleFlowThread(Flow* flow){
	pthread_t thread;
	if(pthread_create(&thread, NULL, handleFlow, (void*) flow) != 0){
		reportError("Error creating flow handling thread\n");
	}
	return thread;
}

//This function actually handles the incoming flow struct
void* handleFlow(void* flowPtr){

	Flow* flow = (Flow*) flowPtr;

	//Get the random value and its own IP address for verifying the packet
	long randomValue = returnRandomValue();
	char* ownIPAddress = getIPAddress(INTERFACE);

	//If the random value doesn't match in the incoming packet, directly exit the thread
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

//This function sends message to Attacker Gateway to let it stop the attack flow
void requestFlowBlocked(Flow* flow){
	//Start timer
	struct timeval startTime;
	gettimeofday(&startTime, NULL);

	//Block the flow temporarily
	addBlockedFlow(flow->attackerIP, flow->victimIP, T_TEMP);

	//Populate the flow struct with information needed for the Attacker Gateway to examine
	flow->messageType = AITF_BLOCKING_REQUEST;
	flow->nonce2 = createNonce(flow->attackerIP, flow->victimIP);
	char* attackerGatewayIP = convertIPAddress(flow->routeRecord->slot1->ipAddress);

	//Send the flow to the Attacker Gateway IP address and store the fd for further handshake
	int connectionFd = sendFlow(attackerGatewayIP, TCP_RECEIVING_PORT, flow);
	Flow* responseFlow = receiveFlowWithOpenConnection(connectionFd);

	//The attacker gateway did not respond, so escalation takes place
	if(responseFlow == NULL){
		escalateFlow(flow);
		return;
	}

	//If the path we had wasn't right, or if we detected someone tampering with our messages, we will just block locally
	if(responseFlow->messageType != AITF_REQUEST_REPLY || flow->nonce2 != responseFlow->nonce2){
		waitMilliseconds(T_LONG);
		removeBlockedFlowAndCountViolations(flow->attackerIP, flow->victimIP);
		return;
	}

	//Everything else seems to be working up to this point, so respond to the messages
	responseFlow->messageType = AITF_REPLY_ACKNOWLEDGEMENT;
	sendFlowWithOpenConnection(connectionFd, responseFlow);
	close(connectionFd);

	//Add entry to the shadow filtering table in case the attack flow happens again shortly
	addEntryToShadowFilteringTable(flow);

	//Wait for T-temp before removing the filter
	while(hasTimeElapsed(&startTime, T_TEMP) == FALSE){
		waitMilliseconds(T_TEMP / 10);
	}
	printf("About to remove flow\n");
	removeBlockedFlowAndCountViolations(flow->attackerIP, flow->victimIP);
		

}

//This function handles the escalation case of the attack flow by contacting the next gateway
void escalateFlow(Flow* flow){

	//Set up the messsage type and get the IP address of that gateway
	flow->messageType = AITF_ESCALATION_REQUEST;
	RouteRecord* rr = flow->routeRecord;
	RouteRecordSlot* slot = rr->slot2;

	//If there is no information or I'm the next available gateway, block locally.
	if(slot == NULL || (slot->ipAddress != NULL && compareIPAddresses(slot->ipAddress, thisGatewayIP) == TRUE)){
		addBlockedFlow(flow->attackerIP, flow->victimIP, T_LONG);
	}
	else{
		//Otherwise, contact the gateway closest to the Attack Gateway
		char* nextGatewayIP = convertIPAddress(slot->ipAddress);
		sendFlow(nextGatewayIP, TCP_RECEIVING_PORT, flow);
	}
}