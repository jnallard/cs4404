all: clean shared.o attacker attackerGateway victim victimGateway

LINK_COMMAND=-Wall -pthread -lnfnetlink -lnetfilter_queue -o
LINK_FILES=shared.o routeRecord.o

shared.o: shared.c shared.h
	gcc -Wall -pthread -c shared.c

attacker: attacker.o $(LINK_FILES)
	gcc attacker.o $(LINK_FILES) $(LINK_COMMAND) attacker

attacker.o: attacker.c shared.h
	gcc -Wall -c attacker.c

attackerGateway: attackerGateway.o $(LINK_FILES)
	gcc attackerGateway.o $(LINK_FILES) $(LINK_COMMAND) attackerGateway

attackerGateway.o: attackerGateway.c shared.h
	gcc -Wall -c attackerGateway.c

victim: victim.o $(LINK_FILES)
	gcc victim.o $(LINK_FILES) $(LINK_COMMAND) victim

victim.o: victim.c shared.h
	gcc -Wall -c victim.c

victimGateway: victimGateway.o $(LINK_FILES)
	gcc victimGateway.o $(LINK_FILES) $(LINK_COMMAND) victimGateway

victimGateway.o: victimGateway.c shared.h
	gcc -Wall -c victimGateway.c

routeRecord.o: routeRecord.c shared.h shared.c
	gcc -Wall -c routeRecord.c

clean:
	rm -f *.o
	rm -f attacker
	rm -f attackerGateway
	rm -f victim
	rm -f victimGateway
	rm -f routeRecord


