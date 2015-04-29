#!/bin/bash
#need: sudo apt-get install sshpass
#Need to run this script in the top code directory
a=$1' cs4404@10.4.12.'$2':~/shared'
echo 'Pushing onto shared...'
sshpass -p 'cs4404' scp -q $a
sshpass -p 'cs4404' ssh cs4404@10.4.12.$2 -t "cd ~/shared;make"
echo "Done"