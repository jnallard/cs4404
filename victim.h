#ifndef VICTIM_H
#define VICTIM_H

#define UDP_PORT 4404
#define INTERFACE "eth0"
#define ATTACK_COUNT_THRESHOLD 20

typedef struct AttackList {
	char* srcIP;
	int count;
	struct AttackList* next;
} AttackList;

AttackList* updateAttackCount(AttackList* attackList, char* attackerSrcIP, AttackList** entry);

#endif
