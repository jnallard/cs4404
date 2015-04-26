#include "shared.h"
#include "attackerGateway.h"


extern int aitfListeningSocket;
pthread_t aitfListeningThread;
pthread_t routeRecordThread;

char* ownIPAddress;


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

void* handleAITFHandshake(void *tableEntry){
	//TODO argument ->receive clientfd 
	//TODO add an extra argument in receiveAITFMessage() pass in client fd and use it here to send and receive using the same fd
	AITFMessageListEntry* entry = (AITFMessageListEntry*)tableEntry;
	Flow* flow = entry->flow;
	int clientfd = entry->clientfd;

	//modify the packet to include nonce 1 and renewed message type
	int nonce = createNonce(getInAddr(ownIPAddress), flow->victimIP);
	flow->nonce1 = nonce;
	flow->messageType = AITF_REQUEST_REPLY;

	//send the packet back to the victim using clientfd
	char *flowString = writeFlowStructAsNetworkBuffer(flow);

	if(send(clientfd, flowString, MAX_FLOW_SIZE, 0) < 0){
		printf("Error occurred when sending request reply\n");
	}

	//waiting for the reply acknowledgement
	char buf[2000];
	int count;
	memset(buf, 0, MAX_FLOW_SIZE + 10);
	count = recv(clientfd, buf, MAX_FLOW_SIZE, 0);
	buf[count] = '\0';
 	printf("Acknowledgement packet received. \n");
	Flow *ackFlow = readAITFMessage(buf);

	//check nonce value
	if(ackFlow->nonce1 != nonce){
		//if nonce value not correct, thread finishes
		return NULL;
	}














	return NULL;

}

int main(int argc, char* argv[]){

	struct sigaction action;

	memset(&action, 0, sizeof (struct sigaction));
	action.sa_handler = sigterm;
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);

	struct timeval startTime;
	gettimeofday(&startTime, NULL);

	initializeShadowFilteringTableEntry();
	routeRecordThread = startRouteRecordThread();
	aitfListeningThread = createAITFListeningThread(TCP_RECEIVING_PORT);
	AITFMessageListEntry* receivedEntry = NULL;

	//get random value from route record thread
	long randomValue = returnRandomValue();

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
				//check to see if the flow is in shadow filtering table once	
				if(isInShadowFilteringTable(receivedEntry->flow) == 1){
					//disconnect Attacker
					//TODO disconnect attacker

				} else {

					//spread out a new thread and use the client fd to further handle the handshake
					pthread_t thread;
					if(pthread_create(&thread, NULL, handleAITFHandshake, receivedEntry) != 0){
						reportError("Error creating thread to handle AITF message\n");

					}




				}



			} else {
				//TODO send correct path to victim gateway
			}



		}
		

		waitMilliseconds(100);



	}

	killThread(aitfListeningThread);
	killThread(routeRecordThread);




	return 0;
}