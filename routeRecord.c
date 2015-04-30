//Route Record
//jnallard, yyan
#include "shared.h"


//sudo apt-get install libnetfilter-queue-dev

//Code started from examples here:
//http://www.netfilter.org/projects/libnetfilter_queue/doxygen/group__LibrarySetup.html
//http://www.netfilter.org/projects/libnetfilter_queue/doxygen/group__Queue.html

typedef struct RRFilterEntry {
	struct in_addr* source;
	struct in_addr* dest;
	struct timeval* timeStart;
	int delayedCountTime;
	int count;
	struct RRFilterEntry *next;
} RRFilterEntry;

RRFilterEntry* rrFilterEntryHead = NULL;
pthread_mutex_t rrFilteringLock;

struct in_addr* gatewayAddr;
long randomValue = 0;

	//code learned from udp4.c in http://www.pdbuchan.com/rawsock/rawsock.html
unsigned short csum(unsigned short *buf, int nwords)
{      
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)

            sum += *buf++;

    sum = (sum >> 16) + (sum &0xffff);

    sum += (sum >> 16);

    return (unsigned short)(~sum);

}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	struct nfq_data *nfa, void *data)
{
	u_int32_t id = -1;
	struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
		// printf("hw_protocol=0x%04x hook=%u id=%u ",
		//ntohs(ph->hw_protocol), ph->hook, id);

		char* packet_data = (char*) calloc(1, 10000);
		char* packet_data_2 = (char*) calloc(1, 10000);
		int count = nfq_get_payload(nfa, (unsigned char**)&packet_data);
		// printf("count: [%d], ", count);

		unsigned char protocol = (unsigned char) packet_data[9];

		//Get the source and destination IPs
		char srcIP[33];
		inet_ntop(AF_INET, packet_data+12, srcIP, INET_ADDRSTRLEN);
		srcIP[32] = '\0';
		char destIP[33];
		inet_ntop(AF_INET, packet_data+16, destIP, INET_ADDRSTRLEN);
		destIP[32] = '\0';

		struct in_addr* destAddr = getInAddr(destIP);
		struct in_addr* sourceAddr = getInAddr(srcIP);


		//printf("protocol: [%d], source [%s], dest[%s]\n", (unsigned int) protocol, srcIP, destIP);

		//If we're blocking the flow, drop the packet.
		if(checkForFilteredFlows(sourceAddr, destAddr) == TRUE){
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		}

		//Means the route record shim is not already there, so add it.
		if(protocol == 17){
			RouteRecord* rr = createRouteRecord(gatewayAddr, randomValue);
			char* rr_buf = writeRouteRecordAsNetworkBuffer(rr);

			memcpy(packet_data_2, packet_data + 20, count - 20);
			memcpy(packet_data + 20, rr_buf, MAX_RR_HEADER_SIZE);
			memcpy(packet_data + 20 + MAX_RR_HEADER_SIZE, packet_data_2, count - 20);
			packet_data[9] = (char) ROUTE_RECORD_PROTOCOL;
			
			//getting new length
			short length = (short)MAX_RR_HEADER_SIZE;
			short* oldLength = (short*)(packet_data + 2);
			short newLength = length + ntohs(*oldLength);
			*oldLength = htons(newLength);

			//checksum
			memset(packet_data + 10, 0, 2);
			unsigned short updatedChecksum = csum((unsigned short*)packet_data ,10);
			memcpy(packet_data + 10, &updatedChecksum, 2);


			// printf("Modifying Packet\n\n");
		}
		else{
			// CHange the route record to add new gateway information
			RouteRecord* rr = readRouteRecord(packet_data + 20);
			addGatewayInfo(rr, gatewayAddr, randomValue);


			char* rr_buf = writeRouteRecordAsNetworkBuffer(rr);
			memcpy(packet_data + 20, rr_buf, MAX_RR_HEADER_SIZE);
		}

		return nfq_set_verdict(qh, id, NF_ACCEPT, count + MAX_RR_HEADER_SIZE, (unsigned char*) packet_data);
	}

	// printf("entering callback\n\n");
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void* routeRecordMain(void* arg){

	randomValue = createLongRandomValue();
	char* gatewayIP = getIPAddress(INTERFACE);
	gatewayAddr = getInAddr(gatewayIP);

	initializeRRFilterList();

	struct nfq_handle* h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	//nfq_callback* cb = (nfq_callback*) calloc(1, sizeof(nfq_callback));
	printf("binding this socket to queue '0'\n");
	struct nfq_q_handle* qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}
	int fd = nfq_fd(h);
	int rv = -1;
	char* buf = (char*) calloc(1, 100001);
	while ((rv = recv(fd, buf, 10000, 0)) >= 0) {
		// printf("pkt received\n received: [%d]\n\n", rv);
		nfq_handle_packet(h, buf, rv);
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

	printf("closing library handle\n");
	nfq_close(h);

	pthread_exit(NULL);
}

long returnRandomValue(){
	return randomValue;
}

//initialize the AITF message list to point to null and the lock
void initializeRRFilterList(){
	rrFilterEntryHead = NULL;
	rrFilteringLock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
}


//This function will manage blocking flows using iptables.
//source, can be null for any address, or set to the correct ip
//dest, can be null for any address, or set to the correct ip
//adding, defines if you want to remove a firewall rule (FALSE), or add one (TRUE)
void addBlockedFlow(struct in_addr* source, struct in_addr* dest, int delayedCountTime){

	RRFilterEntry *entry = (RRFilterEntry*) calloc(1, sizeof(RRFilterEntry));

	struct timeval* currentTime = (struct timeval*)malloc(sizeof(struct timeval));
	gettimeofday(currentTime, NULL);

	entry->source = source;
	entry->dest = dest;
	entry->timeStart = currentTime;
	entry->next = NULL;
	entry->count = 0;
	entry->delayedCountTime = delayedCountTime;

	pthread_mutex_lock(&(rrFilteringLock));

	if(rrFilterEntryHead == NULL){
		rrFilterEntryHead = entry;
	} else {
		RRFilterEntry *tmp = rrFilterEntryHead;
		while(tmp->next != NULL){
			tmp = tmp->next;
		}
		tmp->next = entry;
	}

	pthread_mutex_unlock(&(rrFilteringLock));

	printf("Flow is blocked with the source IP[%s], dest IP[%s] for [%d] milliseconds.\n", 
		convertIPAddress(source), convertIPAddress(dest), delayedCountTime);
}


int removeBlockedFlowAndCountViolations(struct in_addr* source, struct in_addr* dest){
	int count = 0;
	pthread_mutex_lock(&(rrFilteringLock));

	printf("Grabbed mutex. \n");

	if(rrFilterEntryHead != NULL){


		printf("About to release mutex. \n");
		RRFilterEntry *tmp = rrFilterEntryHead;
		RRFilterEntry *previous = NULL;
		while((compareIPAddresses(source, tmp->source) != TRUE || compareIPAddresses(dest, tmp->dest) != TRUE) && tmp->next != NULL){

				previous = tmp;
				tmp = tmp->next;
		}
		
		if(compareIPAddresses(source, tmp->source) == TRUE && compareIPAddresses(dest, tmp->dest) == TRUE){
			count = tmp->count;
			if(previous != NULL){
				previous->next = tmp->next;
			}
			else{
				rrFilterEntryHead = tmp->next;
			}

			//free(tmp->source);
			//free(tmp->dest);
			free(tmp->timeStart);
			free(tmp);
		}
	}


	printf("About to release mutex. \n");
	pthread_mutex_unlock(&(rrFilteringLock));

	printf("Block is removed with the source IP[%s], dest IP[%s] with [%d] violations.\n", 
		convertIPAddress(source), convertIPAddress(dest), count);

	return count;
}

int checkForFilteredFlows(struct in_addr* source, struct in_addr* dest){

	pthread_mutex_lock(&(rrFilteringLock));

	RRFilterEntry* tmp = rrFilterEntryHead;
	while(tmp != NULL){
		if((tmp->source == NULL || compareIPAddresses(source, tmp->source) == TRUE) 
			&& (tmp->dest == NULL || compareIPAddresses(dest, tmp->dest) == TRUE) ) {
			if(hasTimeElapsed(tmp->timeStart, tmp->delayedCountTime) == TRUE){
				tmp->count = tmp->count + 1;
			}
			printf("Block flow is detected with the source IP[%s], dest IP[%s] with [%d] violations.\n", 
				convertIPAddress(source), convertIPAddress(dest), tmp->count);

			pthread_mutex_unlock(&(rrFilteringLock));
			return TRUE;
		}

		tmp = tmp->next;
	}
	
	pthread_mutex_unlock(&(rrFilteringLock));

	return FALSE;
}
