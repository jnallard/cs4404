#ifndef SHARED_H__
#define SHARED_H__

//Shared.h This file has all of our library includes, most of the shared constants, structs
//and prototypes for shared.c and routeRecord.c functions

#include <sys/time.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <time.h>
#include <ifaddrs.h>
#include <netinet/in.h> 
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <signal.h>
#include <sys/wait.h>

//Boolean constants
#define TRUE 0
#define FALSE 1

//Sizes for our Flow and RouteRecords
#define ROUTE_RECORD_SLOT_SIZE 12
#define MAX_RR_HEADER_SIZE 52
#define MAX_FLOW_SIZE 72

//Network sending and binding information
#define FLOW_SENDING_PORT "4405"
#define INTERFACE "eth0"
#define ROUTE_RECORD_PROTOCOL 200
#define VICTIM_IP "10.4.12.6"
#define NON_VICTIM_IP "10.4.12.7"
#define VICTIM_GATEWAY_IP "10.4.12.5"
#define UDP_PORT 4404
#define TCP_RECEIVING_PORT 4406

//chosen value for contants; see results section
//time are in milliseconds
#define T_LONG 10000
#define T_TEMP 1000
#define T_SEND 100
#define T_TABLE_CHECK 1000

//Six types of AITF message
#define AITF_BLOCKING_REQUEST 1
#define AITF_REQUEST_REPLY 2
#define AITF_REPLY_ACKNOWLEDGEMENT 3
#define AITF_ESCALATION_REQUEST 4
#define AITF_REQUEST_REPLY_NEW_PATH 5
#define AITF_BLOCKING_REQUEST_VICTIM 6

//This struct is used for our route record slots, containign ip addresses and random values
typedef struct RouteRecordSlot {
	struct in_addr* ipAddress;
	long randomValue;
} RouteRecordSlot;

//This struct containts our route record information: index, size, and the 4 slots
typedef struct RouteRecord {
	short index;
	short size;
	RouteRecordSlot* slot1;
	RouteRecordSlot* slot2;
	RouteRecordSlot* slot3;
	RouteRecordSlot* slot4;

} RouteRecord;

//This represents an AITFMessage and FLow, contains source/dest information, nonces, type, and a route record.
typedef struct Flow {
	struct in_addr* attackerIP;
	struct in_addr* victimIP;
	int nonce1;
	int nonce2;
	int messageType;
	RouteRecord* routeRecord;

} Flow;

//This is a list of flows, with clientFds to keep track of the connection the flow came from
typedef struct AITFMessageListEntry {
	Flow *flow;
	int clientfd;
	struct AITFMessageListEntry *next;
} AITFMessageListEntry;

//the socket for listening to aitf messages/flows
int aitfListeningSocket;

//Functions for timer
void waitMilliseconds(int millisecondsToWait);
int hasTimeElapsed(struct timeval* startTime, int milliseconds);

//Route Record Functions
RouteRecord* readRouteRecord(char* networkLayerPacketInfo);
RouteRecord* createRouteRecord(struct in_addr* ipAddress, long randomValue);
void addGatewayInfo(RouteRecord* routeRecord, struct in_addr* ipAddress, long randomValue);
char* writeRouteRecordAsNetworkBuffer(RouteRecord* routeRecord);

//Flow creating, sending, and receiving functions
Flow* createFlowStruct(struct in_addr* victimIP, struct in_addr* attackerIP, 
	RouteRecord* routeRecord, int nonce1, int nonce2, int messageType);
int sendFlow(char* destIP, int port, Flow* flow);
int sendFlowWithOpenConnection(int connectionFd, Flow* flow);
Flow* receiveFlowWithOpenConnection(int connectionFd);
Flow* readAITFMessage(char* flowInfo);
char* writeFlowStructAsNetworkBuffer(Flow* flow);

//Random number generators
int createNonce(struct in_addr* sourceIP, struct in_addr* destIP);
long createLongRandomValue();
int createRandomInt();

//AITF messages list objects
AITFMessageListEntry *messageListPtr;
pthread_mutex_t lock; //prevent race condition

//Functions for threads receiving AITF messages
pthread_t createAITFListeningThread(int port);
void* listenToAITFMessage(void *portNum);
AITFMessageListEntry* receiveAITFMessage();
void initializeAITFMessageList();
void updateAITFMessageList(Flow* newAITFMessage, int clientfd);

//Free memory
void freeFlow(Flow *flow);
void freeRouteRecord(RouteRecord *rr);
void freeRouteRecordSlot(RouteRecordSlot *rrs);

void killThread(pthread_t thread);

void reportError(char* errorMessage);

//IP getting information
char* getIPAddress(char* interface);
struct in_addr* getInAddr(char* IPAddress);
char* convertIPAddress(struct in_addr* ipAddressStruct);
int compareIPAddresses(struct in_addr* ip1, struct in_addr* ip2);


//For shadow filtering table
typedef struct ShadowFilteringTableEntry {
	Flow *flow;
	struct timeval* startTime;
	struct ShadowFilteringTableEntry *next;
	int count;
} ShadowFilteringTableEntry;


ShadowFilteringTableEntry *headTableEntry;
pthread_mutex_t filteringTableLock; //prevent race condition

//Shadow FIltering prototypes
void initializeShadowFilteringTableEntry();
void addEntryToShadowFilteringTable(Flow* flow);
int isInShadowFilteringTable(Flow* flow);
void updateShadowFilteringTable();

//Route Record function prototypes
pthread_t startRouteRecordThread();
void* routeRecordMain(void* arg);
long returnRandomValue();
void addBlockedFlow(struct in_addr* source, struct in_addr* dest, int delayedCountTime);
int removeBlockedFlowAndCountViolations(struct in_addr* source, struct in_addr* dest);
int checkForFilteredFlows(struct in_addr* source, struct in_addr* dest);
void initializeRRFilterList();


int checkForCorrectRandomValue(char* ipAddress, long randomValue, Flow* receivedFlow);

#endif



