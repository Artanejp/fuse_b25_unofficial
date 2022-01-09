#!/bin/sh

# Note: You should set DEVICES LIST BELOW.Will improve setting.
DEVICES="8 9 10 11"

#OPTS="--eit --utc --conv"
#OPTS="-o sync_read -o big_writes -s "
OPTS=""

for devno in ${DEVICES}; do
  /usr/local/sbin/b25dir ${devno}
  /usr/local/bin/fuse_b25 /dev/dvb/adapter${devno} ${OPTS} -o allow_other
done
exit 0 
