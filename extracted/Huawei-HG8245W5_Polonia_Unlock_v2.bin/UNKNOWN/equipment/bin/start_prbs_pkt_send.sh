#!/bin/sh

up_port_id=`cat /mnt/jffs2/equipment/bin/up_port_id_file`
echo "destPort=$up_port_id, burstRate=$1, pktLen=$2"
ponmode=$(cat /mnt/jffs2/xpon_mode)
if [ $ponmode -eq 1 ]; then
        sndhlp 0 0x20002046 0x46 4 200
        taskset 1 /mnt/jffs2/equipment/bin/diag rt_misc set burstPacket destPort gpon streamID 0 infiniteMode burstRate $1 pktLen $2 pktData 004b90b72e8b000a0b0c0101810000c8080045000069641940007f06c1b90a0b0a01c0a8010836867b215603d47c3b24073f501032001e6b0000000a00000000c8a266770000000080eca70100000000000000003031dc0158eca7011c17019b1c179b0090eca70190eca7015ba166770100000058eda701000000
else
        taskset 1 /mnt/jffs2/equipment/bin/diag rt_misc set burstPacket destPort $up_port_id infiniteMode burstRate $1 pktLen $2 pktData 6c4b90b72e8b000a0b0c0101080045000028641940007f06c1fa0a0b0a01c0a8010836867b215603d47c3b24073f50103200898d0000000a00000000
fi

