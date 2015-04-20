all: clean shared.o attacker victim routeRecord

shared.o: shared.c shared.h
	gcc -Wall -pthread -c shared.c

attacker: attacker.o shared.o
	gcc -Wall -pthread attacker.o shared.o -o attacker

attacker.o: attacker.c shared.h
	gcc -Wall -c attacker.c

victim: victim.o shared.o
	gcc -Wall victim.o shared.o -o victim

victim.o: victim.c shared.h
	gcc -Wall -c victim.c

routeRecord: routeRecord.o shared.o
	gcc -Wall routeRecord.o shared.o -o routeRecord

routeRecord.o: routeRecord.c shared.h
	gcc -Wall -c routeRecord.c

clean:
	rm -f *.o
	rm -f attacker
	rm -f victim
	rm -f routeRecord


