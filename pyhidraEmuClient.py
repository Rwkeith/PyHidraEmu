from multiprocessing import shared_memory
import struct
from enum import Enum

class Command(Enum):
    SHUTDOWN = b'\x01'
    GOTO_LISTING = b'\x02'


class Packet:
    def __init__(self, message_type, payload):
        self.message_type = message_type
        self.payload = payload

class PyhidraEmuClient:
    def __init__(self):
        self.server_shm = self.connect_to_server()

    def connect_to_server(self):
            shm_a = None
            print("[PYHIDRA-EMU] Attempting to establish IPC handshake with ghidra client interpreter...")
            try:
                shm_a = shared_memory.SharedMemory(create=False, name='pyhidraEmu')
            except:
                print('[PYHIDRA-EMU] Was unable to find \'pyhidraEmu\' shared memory for IPC. Was Ghidra launched using \'pyhidraw\' from a console, and is a CodeBrowser window open with the serverStart.py script running?')
                raise ValueError()
                return shm_a

            print('[PYHIDRA-EMU] Found shared memory for IPC!')
            return shm_a

    def send_packet(self, message_type: bytes, payload: bytes):
        packet = Packet(message_type, payload)
        raw_packet = struct.pack('<bi', int.from_bytes(packet.message_type.value), len(packet.payload)) + packet.payload
        self.server_shm.buf[:len(raw_packet)] = raw_packet
    def goto_address(self, address: int):
        self.send_packet(Command.GOTO_LISTING, struct.pack('<Q', address))
