#!/bin/bash
#need: sudo apt-get install sshpass
#Need to run this script in the top code directory
a=$1' cs4404@10.4.12.1:~/shared'
b=$1' cs4404@10.4.12.2:~/shared'
c=$1' cs4404@10.4.12.3:~/shared'
d=$1' cs4404@10.4.12.4:~/shared'
e=$1' cs4404@10.4.12.5:~/shared'
f=$1' cs4404@10.4.12.6:~/shared'
g=$1' cs4404@10.4.12.7:~/shared'

echo 'Pushing onto shared...'
sshpass -p 'cs4404' scp -q -r $a
sshpass -p 'cs4404' ssh cs4404@10.4.12.1 -t "cd ~/shared;make"

sshpass -p 'cs4404' scp -q -r $b
sshpass -p 'cs4404' ssh cs4404@10.4.12.2 -t "cd ~/shared;make"

sshpass -p 'cs4404' scp -q -r $c
sshpass -p 'cs4404' ssh cs4404@10.4.12.3 -t "cd ~/shared;make"

sshpass -p 'cs4404' scp -q -r $d
sshpass -p 'cs4404' ssh cs4404@10.4.12.4 -t "cd ~/shared;make"

sshpass -p 'cs4404' scp -q -r $e
sshpass -p 'cs4404' ssh cs4404@10.4.12.5 -t "cd ~/shared;make"

sshpass -p 'cs4404' scp -q -r $f
sshpass -p 'cs4404' ssh cs4404@10.4.12.6 -t "cd ~/shared;make"

sshpass -p 'cs4404' scp -q -r $g
sshpass -p 'cs4404' ssh cs4404@10.4.12.7 -t "cd ~/shared;make"

echo "Done"