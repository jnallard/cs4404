//Route Record
//jnallard, yyan
#include "shared.h"

#define ROUTE_RECORD_PROTOCOL 200

//sudo apt-get install libnetfilter-queue-dev

//Code started from examples here:
//http://www.netfilter.org/projects/libnetfilter_queue/doxygen/group__LibrarySetup.html
//http://www.netfilter.org/projects/libnetfilter_queue/doxygen/group__Queue.html



struct in_addr* gatewayAddr;
long randomValue = 0;


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	struct nfq_data *nfa, void *data)
{
	u_int32_t id = -1;
	struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
		ntohs(ph->hw_protocol), ph->hook, id);

		char* packet_data = (char*) calloc(1, 10000);
		char* packet_data_2 = (char*) calloc(1, 10000);
		int count = nfq_get_payload(nfa, (unsigned char**)&packet_data);
		printf("count: [%d], ", count);

		int protocol = (int) packet_data[9];
		printf("protocol: [%d]", protocol);

		//Means the route record shim is not already there, so add it.
		if(protocol != ROUTE_RECORD_PROTOCOL){
			RouteRecord* rr = createRouteRecord(gatewayAddr, randomValue);
			char* rr_buf = writeRouteRecordAsNetworkBuffer(rr);

			memcpy(packet_data_2, packet_data + 20, count - 20);
			memcpy(packet_data + 20, rr_buf, MAX_RR_HEADER_SIZE);
			memcpy(packet_data + 20 + MAX_RR_HEADER_SIZE, packet_data_2, count - 20);
			packet_data[9] = (char) ROUTE_RECORD_PROTOCOL;
			printf("Modifying Packet\n\n");
		}
		else{
			// CHange the route record to add new gateway information
			RouteRecord* rr = readRouteRecord(packet_data + 20);
			addGatewayInfo(rr, gatewayAddr, -1l);

			char* rr_buf = writeRouteRecordAsNetworkBuffer(rr);
			memcpy(packet_data + 20, rr_buf, MAX_RR_HEADER_SIZE);
		}

		return nfq_set_verdict(qh, id, NF_ACCEPT, count + MAX_RR_HEADER_SIZE, (unsigned char*) packet_data);
	}

	printf("entering callback\n\n");
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void* routeRecordMain(void* arg){
	randomValue = createLongRandomValue();
	char* gatewayIP = getIPAddress(INTERFACE);
	gatewayAddr = getInAddr(gatewayIP);

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
		printf("pkt received\n received: [%d]\n\n", rv);
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
