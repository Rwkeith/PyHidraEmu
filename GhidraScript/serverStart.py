from multiprocessing import shared_memory
from enum import Enum
import struct
import time
import threading
from ghidra.app.script import GhidraState
from ghidra.app.script import GhidraScript

class Command(Enum):
    SHUTDOWN = b'\x01'
    GOTO_LISTING = b'\x02'


class Packet:
    def __init__(self, message_type, payload):
        self.message_type = message_type
        self.payload = payload

class PyhidraEmuServer(threading.Thread):
    def __init__(self):
        super(PyhidraEmuServer, self).__init__()
        self.daemon = True
        self.server_shm = None
        self.init_shared_memory()
        self.last_goto_addr = None


        # self.shutdown_via_ipc()

    def run(self):
        print("[PYHIDRA-EMU] Server thread is running!")
        self.is_serving = True
        self.command_handler()
        print("[PYHIDRA-EMU] Server thread is exiting!")

    def __del__(self):
        self.do_shutdown()
        self.shutdown()

    def init_shared_memory(self):
        try:
            self.server_shm = shared_memory.SharedMemory(create=True, size=0x100, name="pyhidraEmu")
        except:
            print("[PYHIDRAEMU-SERVER] Shared memory still exists for IPC, reusing.")
            self.server_shm = shared_memory.SharedMemory(name='pyhidraEmu')

        print("[PYHIDRAEMU-SERVER] Initialized shared memory for IPC.")
        return True

    def get_packet(self) -> Packet:
        data_len = None
        packet = Packet(0, b'')
        packet.message_type = bytes(self.server_shm.buf[:1])
        if packet.message_type == Command.GOTO_LISTING.value:
            print('Received Goto Listing Packet.')
            packet.payload = bytes(self.server_shm.buf[1:])
        elif packet.message_type == Command.SHUTDOWN.value:
            print('Received Shutdown Packet.')

        return packet

    def command_handler(self):
        print("[PYHIDRAEMU-SERVER] Entered main command handler")
        packet = Packet(0, b'')
        while packet.message_type != Command.SHUTDOWN:
            time.sleep(1)
            packet = self.get_packet()
            if packet.message_type == Command.GOTO_LISTING.value:
                address = struct.unpack('<Q', packet.payload[4:12])[0]
                self.goto_address(address)

            if packet.message_type == Command.SHUTDOWN.value:
                self.do_shutdown()
                break
    def goto_address(self, address: int):
        # gs = getState()
        addrObj = toAddr(address)
        print(f"currentAddress: {hex(int(currentAddress.toString(), 16))} , addrObj: {hex(int(addrObj.toString(), 16))}")
        if self.last_goto_addr != address:
            self.last_goto_addr = address
            print(f'Going to address {hex(address)}')
            goTo(addrObj)
            # currentAddress doesn't update when using this....
            # gs.setCurrentAddress(addrObj)


    def do_shutdown(self):
        self.server_shm.close()
        self.server_shm.unlink()
        print('[PYHIDRAEMU-SERVER] Closed and unlinked server shared memory')

    def shutdown_via_ipc(self):
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
    pyEmu_serv = PyhidraEmuServer()
    pyEmu_serv.start()


