#!/bin/sh

up_port_id=`cat /mnt/jffs2/equipment/bin/up_port_id_file`
echo "port=$up_port_id"
/mnt/jffs2/equipment/bin/diag mib dump counter port $up_port_id
