#!/bin/bash
#need: sudo apt-get install sshpass
#Need to run this script in the top code directory
a='. cs4404@10.4.12.1:~/shared'
b='. cs4404@10.4.12.2:~/shared'
c='. cs4404@10.4.12.3:~/shared'
d='. cs4404@10.4.12.4:~/shared'
e='. cs4404@10.4.12.5:~/shared'
f='. cs4404@10.4.12.6:~/shared'
echo 'Pushing onto shared...'
sshpass -p 'cs4404' scp -r $a
sshpass -p 'cs4404' ssh cs4404@10.4.12.1 -t "cd ~/shared;make"

sshpass -p 'cs4404' scp -r $b
sshpass -p 'cs4404' ssh cs4404@10.4.12.2 -t "cd ~/shared;make"

sshpass -p 'cs4404' scp -r $c
sshpass -p 'cs4404' ssh cs4404@10.4.12.3 -t "cd ~/shared;make"

sshpass -p 'cs4404' scp -r $d
sshpass -p 'cs4404' ssh cs4404@10.4.12.4 -t "cd ~/shared;make"

sshpass -p 'cs4404' scp -r $e
sshpass -p 'cs4404' ssh cs4404@10.4.12.5 -t "cd ~/shared;make"

sshpass -p 'cs4404' scp -r $f
sshpass -p 'cs4404' ssh cs4404@10.4.12.6 -t "cd ~/shared;make"
echo "Done"