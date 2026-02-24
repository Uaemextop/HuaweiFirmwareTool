"""Protocol subpackage for hwflash."""
from hwflash.proto.packets import *
from hwflash.proto.worker import OBSCWorker, ONTDevice

__all__ = [
    'PacketType', 'FlashMode', 'UpgradeType', 'RESULT_SUCCESS', 'RESULT_CODES',
    'OBSC_SEND_PORT', 'OBSC_RECV_PORT',
    'DiscoveryPacket', 'ControlPacket', 'DataPacket', 'ResponsePacket',
    'OBSCWorker', 'ONTDevice',
]
