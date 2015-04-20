#ifndef SHARED_H__
#define SHARED_H__

#include <sys/time.h>
#include <netinet/in.h>


#define ROUTE_RECORD_SLOT_SIZE 12
#define MAX_RR_HEADER_SIZE 52
#define MAX_FLOW_SIZE 72

#define FLOW_SENDING_PORT "4404"

//chosen value for contants; see results section
//time are in milliseconds
#define T_LONG 10000
#define T_TEMP 1000
#define T_SEND 100
#define COMPLAINING_THRESHOLD 20


typedef struct RouteRecordSlot {
	int ipAddress;
	long randomValue;
} RouteRecordSlot;

typedef struct RouteRecord {
	short index;
	short size;
	RouteRecordSlot* slot1;
	RouteRecordSlot* slot2;
	RouteRecordSlot* slot3;
	RouteRecordSlot* slot4;

} RouteRecord;

typedef struct AITFMessage {
	struct in_addr* attackerIP;
	struct in_addr* victimIP;
	int nonce1;
	int nonce2;
	int messageType;
	RouteRecord* routeRecord;

} Flow;

typedef struct AITFMessageListEntry {
	Flow *flow;
	struct AITFMessageListEntry *next;
} AITFMessageListEntry;


//Function for timer
void wait(int millisecondsToWait);
int hasTimeElapsed(struct timeval* startTime, int milliseconds);


RouteRecord* readRouteRecord(char* networkLayerPacketInfo);

RouteRecord* createRouteRecord(int ipAddress, long randomValue);
void addGatewayInfo(RouteRecord* routeRecord, int ipAddress, long randomValue);
char* writeRouteRecordAsNetworkBuffer(RouteRecord* routeRecord);

Flow* createFlowStruct(struct in_addr* victimIP, struct in_addr* attackerIP, 
	RouteRecord* routeRecord, int nonce1, int nonce2, int messageType);

int sendFlowStruct(struct in_addr* destIP, Flow* flow);
Flow* receiveFlowStruct();

int createNonce(int sourceIP, int destIP);

char* writeFlowStructAsNetworkBuffer(Flow* flow);


//handle AITF messages
AITFMessageListEntry *AITFMessageListHead;
AITFMessageListEntry *messageListPtr;

void* listenToAITFMessage();
Flow* receiveAITFMessage();
void initializeAITFMessageList();
void updateAITFMessageList(Flow* newAITFMessage);

//Free memory
void freeFlow(Flow *flow);
void freeRouteRecord(RouteRecord *rr);
#endif
