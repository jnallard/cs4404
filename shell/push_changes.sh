#!/bin/bash
a='. cs4404@10.4.12.1:~/shared'
b='. cs4404@10.4.12.2:~/shared'
c='. cs4404@10.4.12.3:~/shared'
d='. cs4404@10.4.12.4:~/shared'
e='. cs4404@10.4.12.5:~/shared'
f='. cs4404@10.4.12.6:~/shared'
echo 'Pushing onto shared...'
scp -r $a
scp -r $b
scp -r $c
scp -r $d
scp -r $e
scp -r $f
echo "Done"
