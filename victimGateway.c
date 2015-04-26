#include "shared.h"
#include "victimGateway.h"

extern int aitfListeningSocket;
pthread_t aitfListeningThread;
pthread_t routeRecordThread;
struct in_addr* thisGatewayIP = NULL;

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
		Flow* flow = receiveAITFMessage(); 
		if(flow != NULL){
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
	manageFlow(flow->attackerIP, flow->victimIP, TRUE);

			
}

void escalateFlow(Flow* flow){

	flow->messageType = AITF_ESCALATION_REQUEST;
	RouteRecord* rr = flow->routeRecord;
	RouteRecordSlot* slot = rr->slot2;

	//If there is no information or I'm the next available gateway, block locally.
	if(slot == NULL || (slot->ipAddress != NULL && compareIPAddresses(slot->ipAddress, thisGatewayIP) == TRUE)){
		manageFlow(NULL, flow->victimIP, TRUE);
	}
	else{
		//Otherwise, contact the gateway closest to the Attack Gateway
		char nextGatewayIP[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, slot->ipAddress, nextGatewayIP, INET_ADDRSTRLEN);
		sendFlow(nextGatewayIP, TCP_RECEIVING_PORT, flow);
	}
}