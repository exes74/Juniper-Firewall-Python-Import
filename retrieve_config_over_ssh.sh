#!/bin/bash
dateToday=`date +%Y%m%d`
for i in '192.168.0.1' '192.168.0.2' '192.168.0.3'   ### LIST OF FW 
do
	echo "Getting config for: $i"
	sshpass -p 'PASSWORD' ssh USERNAME@$i 'show conf|display xml' > `echo $i_$dateToday`  ### ARBITRARY EXPORT FILENAME
done
