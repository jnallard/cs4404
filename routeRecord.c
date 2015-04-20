//Route Record
//jnallard, yyan

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libipq.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

//sudo apt-get install libnetfilter_queue_dev

//Code started from examples here:
//http://www.netfilter.org/projects/libnetfilter_queue/doxygen/group__LibrarySetup.html
//http://www.netfilter.org/projects/libnetfilter_queue/doxygen/group__Queue.html

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
		int count = nfq_get_payload(nfa, &packet_data);
		printf("count: [%d], ", count);
		memcpy(packet_data + count, "Josh", 5);
		printf("Modifying Packet\n\n");
		return nfq_set_verdict(qh, id, NF_ACCEPT, count + 5, (unsigned char*) packet_data);
	}

	printf("entering callback\n\n");
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char* argv[]){
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

	return 0;
}
