import pyhidra
from pyhidra.launcher import DeferredPyhidraLauncher, HeadlessPyhidraLauncher
# launcher = HeadlessPyhidraLauncher(verbose=True)
launcher = DeferredPyhidraLauncher(verbose=False)
launcher.start()
import ghidra
launcher.initialize_ghidra(headless=False)
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.base.project import GhidraProject
from ghidra.program.model.mem import MemoryBlock
from javax.swing import SwingUtilities
from ghidra.program.util import ProgramLocation

import contextlib
import sys

class DummyFile(object):
    def write(self, x): pass

@contextlib.contextmanager
def nostdout():
    save_stdout = sys.stdout
    sys.stdout = DummyFile()
    yield
    sys.stdout = save_stdout


g_flat_api = None
g_program = None
g_project = None

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
        global g_program
        global g_project
        self.flat_api = None
        self.project, self.program = self.init_flat_api(binary_name, proj_path, proj_name)
        g_program = self.program
        g_project = self.project
        self.code_browser, self.code_browser_component = self.launch_codebrowser()
        self.memory = self.program.getMemory()
        self.generic_mem_blocks = self.init_mem_blocks()

    def goto_address(self, address):
        # test run without gui updating, is 0.7s
        progLocation = ProgramLocation(g_program, g_flat_api.toAddr(address))

        # 10.6s runtime
        def myRunnable():
            self.code_browser_component.goTo(g_program, progLocation)

        SwingUtilities.invokeAndWait(myRunnable)

        # without swing thread, 6.9s runtime
        # self.code_browser_component.goTo(g_program, progLocation)

    def init_flat_api(self, binary_name, proj_path, proj_name):
        global g_flat_api
        self.flat_api = pyhidra.open_program(binary_path=binary_name, project_name=proj_name ,project_location=proj_path, analyze=False)
        project, g_flat_api = self.flat_api.__enter__()
        return project, g_flat_api.getCurrentProgram()

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

    def launch_codebrowser(self):
        localToolChest = self.project.getProjectManager().activeProject.getLocalToolChest()
        ltt = localToolChest.getToolTemplates()

        def myRunnable():
            ltt[0].createTool(g_project.project)

        SwingUtilities.invokeAndWait(myRunnable)

        ws = g_project.getProjectManager().activeProject.getToolManager().getWorkspaces()
        def myRunnable1():
            # tools[0].toolServices.launchTool('CodeBrowser', self.program.getDomainFile())
            ws[0].runTool(ltt[0])

        SwingUtilities.invokeAndWait(myRunnable1)
        tools = ws[0].getTools()
        def myRunnable2():
            tools[0].toolServices.launchTool('CodeBrowser', g_program.getDomainFile())

        SwingUtilities.invokeAndWait(myRunnable2)

        tools = ws[0].getTools()
        for tool in tools:
            if tool.getDefaultToolContext():
                return tool, tool.getDefaultToolContext().getGlobalContext().getContextObject().componentProvider
        print('[PYHYDRIA-EMU] Unable to locate CodeBrowser tool with loaded program!')
        raise ValueError()