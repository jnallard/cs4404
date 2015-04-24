#ifndef VICTIM_H
#define VICTIM_H

#define ATTACK_COUNT_THRESHOLD 20

typedef struct AttackList {
	char* srcIP;
	int count;
	struct AttackList* next;
} AttackList;

AttackList* updateAttackCount(AttackList* attackList, char* attackerSrcIP, AttackList** entry);

void sendComplaint();

#endif
