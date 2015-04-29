#!/bin/bash
a='sudo apt-get install make;sudo apt-get install libnetfilter-queue-dev'

sshpass -p 'cs4404' ssh cs4404@10.4.12.1 -t "sh ~/shared/shell/attackerSetup.sh;$a"
sshpass -p 'cs4404' ssh cs4404@10.4.12.2 -t "sh ~/shared/shell/attackerGatewaySetup.sh;$a"
sshpass -p 'cs4404' ssh cs4404@10.4.12.3 -t "sh ~/shared/shell/Gateway2Setup.sh;$a"
sshpass -p 'cs4404' ssh cs4404@10.4.12.4 -t "sh ~/shared/shell/Gateway3Setup.sh;$a"
sshpass -p 'cs4404' ssh cs4404@10.4.12.5 -t "sh ~/shared/shell/victimGatewaySetup.sh;$a"
sshpass -p 'cs4404' ssh cs4404@10.4.12.6 -t "sh ~/shared/shell/victimSetup.sh;$a"
sshpass -p 'cs4404' ssh cs4404@10.4.12.7 -t "sh ~/shared/shell/nonVictimSetup.sh;$a"
echo "Done"