import pyhidra
from pyhidra.launcher import DeferredPyhidraLauncher, HeadlessPyhidraLauncher
launcher = HeadlessPyhidraLauncher(verbose=True)
launcher.start()
import ghidra
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.base.project import GhidraProject
from ghidra.program.model.mem import MemoryBlock

g_flat_api = None

class MemBlock:
    def __init__(self, mem_block: MemoryBlock = None, **kwargs):
        if mem_block:
            self.name: str = mem_block.name
            if str(mem_block.start).find('::'):
                mem_block_start = str(mem_block.start)[str(mem_block.start).find('::')+2:]
                self.start: int = int(mem_block_start, 16)
            else:
                self.start: int = int(str(mem_block.start), 16)

            if str(mem_block.end).find('::'):
                mem_block_end = str(mem_block.end)[str(mem_block.end).find('::')+2:]
                self.end: int = int(mem_block_end, 16)
            else:
                self.end: int = int(str(mem_block.end), 16)

            self.exec: bool = mem_block.execute
            self.write: bool = mem_block.write
            self.size: int = int(str(mem_block.size))
            self.initialized: bool = mem_block.initialized

            if self.initialized:
                self.block_bytes: bytes = bytes(g_flat_api.getBytes(mem_block.start, int(mem_block.size)))
            else:
                self.block_bytes = None

            print(f"[GHIDRA] Added {mem_block.name} from memory mapping {hex(self.start)} - {hex(self.end)}")


class GhidraProgram:
    def __init__(self, binary_name, proj_path, proj_name):
        self.flat_api = None
        self.program = self.init_flat_api(binary_name, proj_path, proj_name)
        self.memory = self.program.getMemory()
        self.generic_mem_blocks = self.init_mem_blocks()


    def init_flat_api(self, binary_name, proj_path, proj_name):
        global g_flat_api
        self.flat_api = pyhidra.open_program(binary_path=binary_name, project_name=proj_name ,project_location=proj_path, analyze=False)
        g_flat_api = self.flat_api.__enter__()
        return g_flat_api.getCurrentProgram()

    def init_mem_blocks(self):
        mem_blocks = self.memory.getBlocks()
        generic_mem_blocks = []
        for mem_block in mem_blocks:
            if mem_block.isOverlay():
                print(f"[GHIDRA] Ignoring block \'{mem_block.name}\' marked as \'Overlay\' ")
                continue
            generic_mem_blocks.append(MemBlock(mem_block))

        generic_mem_blocks.sort(key=lambda memblock: memblock.start)
        return generic_mem_blocks

    def print_memory_layout(self):
        for mem_block in self.generic_mem_blocks:
            print(f"Name: {mem_block.name} Start: {hex(mem_block.start)} End: {hex(mem_block.end)} Size: {hex(mem_block.size)}")
        