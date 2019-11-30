import struct


def disass(binpath):
    with open(binpath, "rb") as f:
        binary = bytearray(f.read())

    i = 0
    asm = ""
    while i < len(binary):
        if binary[i] == 0x1a: # MOVI reg_dst, imm32
            reg_dst = binary[i+1]
            imm = binary[i+2:i+2+4]
            # import pdb; pdb.set_trace()
            asm += "movi r{}, 0x{:08x}\n".format(reg_dst, struct.unpack("I", imm)[0])
            i += 6
        elif binary[i] == 0x1b: # MOV reg_dst, reg_src
            reg_dst = binary[i+1]
            reg_src = binary[i+2]
            asm += "mov r{}, r{}\n".format(reg_dst, reg_src)
            i += 3
        elif binary[i] == 0x0a: # AND reg_dst, reg_src
            reg_dst = binary[i+1]
            reg_src = binary[i+2]
            asm += "and r{}, r{}\n".format(reg_dst, reg_src)
            i += 3
        elif binary[i] == 0x0b: # XOR reg_dst, reg_src
            reg_dst = binary[i+1]
            reg_src = binary[i+2]
            asm += "xor r{}, r{}\n".format(reg_dst, reg_src)
            i += 3
        elif binary[i] == 0xff: # END
            asm += "end"
            i += 1
        else:
            raise Exception("Unknown operation")
    return asm

if __name__ == '__main__':
    asm = disass("./keycheck")
    print(asm)
