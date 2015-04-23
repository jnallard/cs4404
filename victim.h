#ifndef VICTIM_H
#define VICTIM_H

#define UDP_PORT 4404
#define ATTACK_COUNT_THRESHOLD 20

#define TCP_PORT "4405"
#define DESTINATION_IP "127.0.0.1"

typedef struct AttackList {
	char* srcIP;
	int count;
	struct AttackList* next;
} AttackList;

AttackList* updateAttackCount(AttackList* attackList, char* attackerSrcIP, AttackList** entry);

void sendComplaint();

#endif
