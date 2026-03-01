#!/bin/sh

chmod +x /mnt/jffs2/equipment/bin/diag
chmod +x /mnt/jffs2/equipment/bin/get_up_port_id.sh
chmod +x /mnt/jffs2/equipment/bin/start_prbs_pkt_send.sh
chmod +x /mnt/jffs2/equipment/bin/stop_prbs_pkt_send.sh
chmod +x /mnt/jffs2/equipment/bin/display_prbs_statistics.sh

/mnt/jffs2/equipment/bin/get_up_port_id.sh
up_port_id=`cat /mnt/jffs2/equipment/bin/up_port_id_file`
echo "port=$up_port_id"
/mnt/jffs2/equipment/bin/diag mib reset counter port $up_port_id
/mnt/jffs2/equipment/bin/diag oam set parser port $up_port_id action discard
