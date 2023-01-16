import argparse
from ghidraProgram import GhidraProgram
from unicornEmu import UnicornEmu
from pyhidraEmuClient import PyhidraEmuClient

def run_parser():
    parser = argparse.ArgumentParser()

    parser.add_argument("--bin", help="name of the binary in the project")
    parser.add_argument("--path", help="path to the project")
    parser.add_argument("--proj_name", help="name of the project")

    parser.add_argument('--gui', nargs='?', type=bool, const=True, default=False)

    args = parser.parse_args()

    return args

def main():
    args = run_parser()

    if args.gui:
        client = PyhidraEmuClient()

    gp = GhidraProgram(binary_name=args.bin, proj_path=args.path, proj_name=args.proj_name)
    MAIN_START = 0x004006d4
    MAIN_END = 0x00400784
    emu = UnicornEmu(gp=gp, start=MAIN_START, stop=MAIN_END)
    emu.run_emulation()

if __name__ == '__main__':
    main()