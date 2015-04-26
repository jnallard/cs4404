#include "shared.h"
#include "victimGateway.h"

extern int aitfListeningSocket;
pthread_t aitfListeningThread;
pthread_t routeRecordThread;

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
	struct sigaction action;

	memset(&action, 0, sizeof (struct sigaction));
	action.sa_handler = sigterm;
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);

	int running = TRUE;
	struct timeval startTime;
	gettimeofday(&startTime, NULL);
	routeRecordThread = startRouteRecordThread();
	aitfListeningThread = createAITFListeningThread(TCP_RECEIVING_PORT);

	while(running == TRUE){
		if(hasTimeElapsed(&startTime, T_TABLE_CHECK) == TRUE){
			gettimeofday(&startTime, NULL);
			updateShadowFilteringTable();
		}
		Flow* flow = receiveAITFMessage(); 
		if(flow != NULL){
			//handle flow request
		}
		waitMilliseconds(100);
	}

	killThread(aitfListeningThread);
	killThread(routeRecordThread);
	return 0;
}