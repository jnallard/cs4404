#!/bin/bash

sshpass -p 'cs4404' ssh cs4404@10.4.12.1 -t "sh ~/shared/attackerSetup.sh"
sshpass -p 'cs4404' ssh -t cs4404@10.4.12.2 sh attackerGatewaySetup.sh
sshpass -p 'cs4404' ssh -t cs4404@10.4.12.3 sh Gateway2Setup.sh
sshpass -p 'cs4404' ssh -t cs4404@10.4.12.4 sh Gateway3Setup.sh
sshpass -p 'cs4404' ssh -t cs4404@10.4.12.5 sh victimGatewaySetup.sh
sshpass -p 'cs4404' ssh -t cs4404@10.4.12.6 sh victimSetup.sh
echo "Done"
