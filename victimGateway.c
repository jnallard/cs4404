#include "shared.h"
#include "victimGateway.h"

int main(int argc, char* argv[]){
	int running = TRUE;
	struct timeval startTime;
	gettimeofday(&startTime, NULL);
	while(running == TRUE){
		if(hasTimeElapsed(&startTime, T_TABLE_CHECK) == TRUE){
			gettimeofday(&startTime, NULL);
			updateShadowFilteringTable();
		}

		waitMilliseconds(100);
	}
	return 0;
}