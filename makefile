all: clean shared.o attacker attackerGateway victim victimGateway routeRecord

shared.o: shared.c shared.h
	gcc -Wall -pthread -c shared.c

attacker: attacker.o shared.o
	gcc -Wall -pthread attacker.o shared.o -o attacker

attacker.o: attacker.c shared.h
	gcc -Wall -c attacker.c

attackerGateway: attackerGateway.o shared.o
	gcc -Wall -pthread attackerGateway.o shared.o -o attackerGateway

attackerGateway.o: attackerGateway.c shared.h
	gcc -Wall -c attackerGateway.c

victim: victim.o shared.o
	gcc -Wall -pthread victim.o shared.o -o victim

victim.o: victim.c shared.h
	gcc -Wall -c victim.c

victimGateway: victimGateway.o shared.o
	gcc -Wall -pthread victimGateway.o shared.o -o victimGateway

victimGateway.o: victimGateway.c shared.h
	gcc -Wall -c victimGateway.c

routeRecord: routeRecord.o shared.o
	gcc -Wall -pthread routeRecord.o shared.o -lnfnetlink -lnetfilter_queue -o routeRecord

routeRecord.o: routeRecord.c shared.h
	gcc -Wall -c routeRecord.c

clean:
	rm -f *.o
	rm -f attacker
	rm -f attackerGateway
	rm -f victim
	rm -f victimGateway
	rm -f routeRecord


