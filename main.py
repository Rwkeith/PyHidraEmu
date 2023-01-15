import argparse
from ghidraProgram import GhidraProgram
from unicornEmu import UnicornEmu

def run_parser():
    parser = argparse.ArgumentParser()

    parser.add_argument("--bin", help="name of the binary in the project")
    parser.add_argument("--path", help="path to the project")
    parser.add_argument("--proj_name", help="name of the project")

    args = parser.parse_args()
    return args

def main():
    args = run_parser()
    gp = GhidraProgram(binary_name=args.bin, proj_path=args.path, proj_name=args.proj_name)
    MAIN_START = 0x004006d4
    MAIN_END = 0x00400784
    emu = UnicornEmu(gp=gp, start=MAIN_START, stop=MAIN_END)
    emu.run_emulation()
    # # write to EL3 register
    # arm_code = b'eret; mrs x0, CurrentEl; mrs x0, CurrentEl; mrs x0, CurrentEl; mrs x0, CurrentEl; mrs x0, CurrentEl; msr vbar_el3, x0'
    #
    # byte_code, _ = ks.asm(arm_code)
    # # byte_code = ''.join(map(chr, byte_code))
    #
    # mu.hook_add(UC_HOOK_CODE, hook_code)
    # text_base = 0x2000
    # text_size = 0x1000
    # mu.mem_map(text_base, text_size)
    # mu.mem_map(0, 0x1000)
    # mu.mem_write(text_base, bytes(byte_code))
    # mu.mem_write(0, bytes(byte_code[4:]))


    # set EL3??  Can't set EL bits through NZCV reg...chatgpt lies...
    # cpsr = mu.reg_read(UC_ARM64_REG_NZCV)
    # cpsr &= ~(0b111)
    # cpsr |= 0b11
    
    # # cpsr = 0x40000003
    # mu.reg_write(UC_ARM64_REG_NZCV, cpsr)

    # if arch == uc.UC_ARCH_ARM64:
    # if reg_id == arm64_const.UC_ARM64_REG_CP_REG:
    #     reg = uc_arm64_cp_reg()
    #     if not isinstance(opt, tuple) or len(opt) != 5:
    #         raise UcError(uc.UC_ERR_ARG)
    #     reg.crn, reg.crm, reg.op0, reg.op1, reg.op2 = opt
    #     status = reg_read_func(reg_id, ctypes.byref(reg))
    #     if status != uc.UC_ERR_OK:
    #         raise UcError(status)
    #     return reg.val


    # cpsr = mu.reg_read(UC_ARM64_REG_CP_REG, (crn, crm, op0, op1, op2), )


if __name__ == '__main__':
    main()