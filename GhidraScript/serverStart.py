from multiprocessing import shared_memory
from dataclasses import dataclass
from enum import IntEnum, Enum
import struct
import time

class Command(Enum):
    SHUTDOWN = b'\x01'
    GOTO_LISTING = b'\x02'


@dataclass
class Packet:
    def __init__(self, message_type, payload):
        self.message_type = message_type
        self.payload = payload

class PyhidraEmuClient:
    def __init__(self):
        self.server_shm = None
        if self.init_shared_memory():
            self.command_handler()
        else:
            self.shutdown()

    def init_shared_memory(self):
        try:
            self.server_shm = shared_memory.SharedMemory(create=True, size=10, name="pyhidraEmu")
        except:
            return False

        print("[PYHIDRAEMU-SERVER] Initialized shared memory for IPC.")
        return True

    def get_packet(self) -> Packet:
        packet = Packet(0, b'')
        packet.message_type = bytes(self.server_shm.buf[:1])
        if packet.message_type == Command.GOTO_LISTING.value:
            print('Received Goto Listing Packet.')
            data = packet.payload[1:5]
        elif packet.message_type == Command.SHUTDOWN.value:
            print('Received Goto Listing Packet.')
            data = None

        return packet

    def command_handler(self):
        print("[PYHIDRAEMU-SERVER] Entered main command handler")
        packet = Packet(0, b'')
        while packet.message_type != Command.SHUTDOWN:
            time.sleep(1)
            packet: Packet = self.get_packet()
            if packet.message_type == Command.GOTO_LISTING.value:
                self.goto_address(packet.payload)

            if packet.message_type == Command.SHUTDOWN.value:
                self.do_shutdown()
                break
    def goto_address(self, address: int):
        # goTo(toAddr(address))
        print(f'Going to address {hex(address)}')

    def do_shutdown(self):
        self.server_shm.close()
        self.server_shm.unlink()
        print('[PYHIDRAEMU-SERVER] Closed and unlinked server shared memory')

    def shutdown(self):
        print("[PYHIDRAEMU-SERVER] Detected server shared memory, sending server shutdown packet")
        try:
            server_shm = shared_memory.SharedMemory(name="pyhidraEmu")
        except:
            print("[PYHIDRAEMU-SERVER] Unable to open shared memory \'pyhidraEmu\'")
            return



        packet = Packet(Command.SHUTDOWN, b'0')
        raw_packet = struct.pack('<bi', packet.message_type, len(packet.payload)) + packet.payload
        server_shm.buf = raw_packet


if __name__ == '__main__':
    PyhidraEmuClient()


