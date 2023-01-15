from unicorn import *
from unicorn.arm64_const import *
from keystone import *
from unicorn.arm_const import *
from capstone import *
from capstone.arm import *
from consts import arm64_registers
from ghidraProgram import GhidraProgram


# currently supports AARCH64
class virtCPU:
    def __init__(self, mu: Uc = None, sp: int = None):
        self.mu = mu
        if sp:
            self.mu.reg_write(UC_ARM64_REG_SP, sp)

    def print_context(self):
        print('Unicorn register context:')
        for reg in arm64_registers:
            reg_val = self.mu.reg_read(arm64_registers[reg])
            print(f'{reg} : {hex(reg_val)}')

    def set_pstate(self):
        pstate = self.mu.reg_read(UC_ARM64_REG_PSTATE)
        pstate |= 0b1100
        self.mu.reg_write(UC_ARM64_REG_PSTATE, pstate)

    def set_spsr(self):
        # crn = 0b0100
        # crm = 0b0000
        # op0 = 0b11
        # op1 = 0b110
        # op2 = 0b000
        spsr_el3 = self.mu.reg_read(UC_ARM64_REG_CP_REG, (0b0100, 0b0000, 0b11, 0b110, 0b000))
        spsr_el3 |= 0b01101
        self.mu.reg_write(UC_ARM64_REG_CP_REG, (0b0100, 0b0000, 0b11, 0b110, 0b000, spsr_el3))


# currently supports AARCH64
class UnicornEmu:
    def __init__(self, gp: GhidraProgram = None, start: int = None, stop: int = None, make_stack: bool = True, make_heap: bool = True, ignore_protections: bool = True):
        self.PAGE_SIZE = 0x1000
        self.start = start
        self.stop = stop
        self.cs = self.init_capstone()
        self.mu = self.init_unicorn()
        self.ks = self.init_keystone()
        self.gp: GhidraProgram = gp
        self.stack_base = None
        self.stack_size = None
        self.heap_base = None
        self.memory_map = self.init_memory_layout(ignore_protections, make_stack, make_heap)
        self.cpu = self.init_cpu()
        self.init_hooks(ignore_protections)


    def init_capstone(self):
        return Cs(CS_ARCH_ARM64, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)

    def init_unicorn(self):
        return Uc(UC_ARCH_ARM64, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)

    def init_keystone(self):
        return Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

    def init_memory_layout(self, ignore_protections, make_stack, make_heap):
        memory_mappings = [(self.align_down(self.gp.generic_mem_blocks[0].start), self.align_up(self.gp.generic_mem_blocks[0].end))]

        for curr_block in self.gp.generic_mem_blocks:
            last_block = memory_mappings[-1]
            if self.align_down(curr_block.start) <= last_block[1]:
                memory_mappings[-1] = (last_block[0], max(last_block[1], self.align_up(curr_block.end)))
            else:
                memory_mappings.append((self.align_down(curr_block.start), self.align_up(curr_block.end)))


        for mem_range in memory_mappings:
            # For overlapping memory blocks
            print(f"[UNICORN] Mapping memory range {hex(mem_range[0])} - {hex(mem_range[1])}")

            map_size = mem_range[1] - mem_range[0]
            # if ignore_protections:
            self.mu.mem_map(mem_range[0], map_size, UC_PROT_ALL)
            # else:
            #     if curr_mem_block.exec and curr_mem_block.write:
            #         self.mu.mem_map(self.align_down(curr_mem_block.start), self.align_up(curr_mem_block.size), UC_PROT_ALL)
            #     elif curr_mem_block.exec and not curr_mem_block.write:
            #         self.mu.mem_map(self.align_down(curr_mem_block.start),  self.align_up(curr_mem_block.size), UC_PROT_EXEC | UC_PROT_WRITE | UC_PROT_READ)
            #     elif not curr_mem_block.exec and curr_mem_block.write:
            #         self.mu.mem_map(self.align_down(curr_mem_block.start),  self.align_up(curr_mem_block.size),  UC_PROT_WRITE | UC_PROT_READ)
            #     else:
            #         self.mu.mem_map(self.align_down(curr_mem_block.start),  self.align_up(curr_mem_block.size), UC_PROT_READ)


        for mem_block in self.gp.generic_mem_blocks:
            if mem_block.initialized:
                self.mu.mem_write(mem_block.start, mem_block.block_bytes)

        # somewhere after all our other memory blocks
        max_addr = memory_mappings[-1][1]
        # How big should the stack be?  Lets be generous.
        if make_stack:
            max_addr += 0x10000
            self.stack_size = STACK_SIZE = 0x200000

            print(f"[UNICORN] Mapping stack to {hex(max_addr)} - {hex(max_addr + STACK_SIZE)}")
            self.mu.mem_map(max_addr, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
            # Leaving a page of space for args the user may want to put in the stack.
            self.stack_base = (max_addr + self.stack_size) - 0x1000

        # some arbitrary location after the stack
        if make_heap:
            self.heap_base = self.stack_base + 0x10000
            self.heap_size = HEAP_SIZE = 0x400000
            print(f"[UNICORN] Mapping heap to {hex(self.heap_base)} - {hex(self.heap_base + self.heap_size)}")
            self.mu.mem_map(self.heap_base, self.heap_size, UC_PROT_READ | UC_PROT_WRITE)

    def init_cpu(self):
        return virtCPU(self.mu, self.stack_base)

    def hook_code(self, uc, address, size, user_data):
        code = uc.mem_read(address, size)
        instruction = list(self.cs.disasm(bytes(code), size))

        if len(instruction) == 0:
            print(f'>>> 0x{hex(address)}\t{instruction}\tdisasm failure')
        for ins in instruction:
            print(f'>>> {hex(address)}\t{instruction}')

        if address == 0:
            print("PSEUDO BP")


    def is_aligned(self, address):
        aligned_address = address & ~(self.PAGE_SIZE - 1)
        return aligned_address == address

    def align_down(self, address):
        aligned_address = address & ~(self.PAGE_SIZE -1)
        return aligned_address

    def align_up(self, address):
        aligned_address = (address + (self.PAGE_SIZE - 1)) & ~(self.PAGE_SIZE - 1)
        return aligned_address

    def init_hooks(self, ignore_protections):
        for mem_block in self.gp.generic_mem_blocks:
            if ignore_protections:
                self.mu.hook_add(UC_HOOK_CODE, self.hook_code, begin=mem_block.start, end=mem_block.end)
            else:
                if mem_block.exec:
                    self.mu.hook_add(UC_HOOK_CODE, self.hook_code, begin=mem_block.start, end=mem_block.end)

    def run_emulation(self):
        try:
            self.cpu.print_context()
            self.mu.emu_start(self.start, self.stop)
        except UcError as e:
            self.cpu.print_context()
            print(f"UcError occured! {e.errno} , {e.args}")
            raise e

        print("EMULATION COMPLETED SUCCESSFULLY!")
