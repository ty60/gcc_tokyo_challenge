# Reversing report
The same report can be seen here: https://github.com/yasm1/gcc_tokyo_challenge/blob/master/gcc_challenge3_Reversing/report.md

# 1.
The script can also be seen here: https://github.com/yasm1/gcc_tokyo_challenge/blob/master/gcc_challenge3_Reversing/crack.py
```python
import angr
import claripy


BASE_ADDR = 0x400000
def crack():
    proj = angr.Project('./vmgcc')

    flag = claripy.BVS('flag', 8 * 16)
    state = proj.factory.full_init_state(stdin=flag)

    for i in range(16):
        state.solver.add(0x21 <= flag.get_byte(i))
        state.solver.add(flag.get_byte(i) <= 0x7e)

    simgr = proj.factory.simgr(state)
    simgr.explore(find=(BASE_ADDR+0xe34))

    if simgr.found:
        print(simgr.found[0].solver.eval(flag, cast_to=bytes).decode())
    else:
        print("Failed to find valid input")


if __name__ == '__main__':
    crack()
    # cracked flag: ppda(E$$(0!(a!(i
```

# 2.
The disassembler can also be seen here: https://github.com/yasm1/gcc_tokyo_challenge/blob/master/gcc_challenge3_Reversing/disass.py

```python
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
```
