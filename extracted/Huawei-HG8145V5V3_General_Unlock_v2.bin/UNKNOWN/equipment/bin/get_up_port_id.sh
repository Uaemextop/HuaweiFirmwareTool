#!/bin/sh

num9603=`/mnt/jffs2/equipment/bin/diag debug get version | grep RTL9603 | wc -l`
if [ $num9603 -ne 0 ]; then
        echo 4 > /mnt/jffs2/equipment/bin/up_port_id_file
        if [ -f /mnt/jffs2/equipment/bin/diag_9603]; then
            rm -rf /mnt/jffs2/equipment/bin/diag
            mv /mnt/jffs2/equipment/bin/diag_9603 /mnt/jffs2/equipment/bin/diag
        fi
        if [ -f /mnt/jffs2/equipment/lib/librtk_9603.so]; then
            rm -rf /mnt/jffs2/equipment/lib/librtk.so
            mv /mnt/jffs2/equipment/lib/librtk_9603.so /mnt/jffs2/equipment/lib/librtk.so
        fi
else
        echo 5 > /mnt/jffs2/equipment/bin/up_port_id_file
fi
up_port_id=`cat /mnt/jffs2/equipment/bin/up_port_id_file`
echo "up_port_id=$up_port_id"
