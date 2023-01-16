from multiprocessing import shared_memory

class PyhidraEmuClient:
    def __init__(self):
        self.connect_to_server()

    def connect_to_server(self):
            print("[PYHIDRA-EMU] Attempting to establish IPC handshake with ghidra client interpreter...")
            try:
                shm_a = shared_memory.SharedMemory(create=False, name='pyhidraEmu')
            except:
                print('[PYHIDRA-EMU] Was unable to find shared memory for IPC. Was Ghidra launched using \'pyhidraw\' from a console, and is a CodeBrowser window open with the serverStart.py script running?')
                return False

            print('[PYHIDRA-EMU] Found shared memory for IPC!')
            return True