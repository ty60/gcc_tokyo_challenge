import claripy
import struct

def confirm(flag):
    if type(flag) == 'str':
        flag = flag.encode()
    parts = []
    for i in range(4):
        parts.append(struct.unpack("<I", flag[i * 4:i * 4 + 4])[0])

    r0 = (0x41424344 & parts[0]) ^ 0x41404044
    r1 = (0x45464748 & parts[1])  ^ 0x41044748
    r2 = (0x494a4b4c & parts[2]) ^ 0x494a404c
    r3 = 0x4d424340
    r4 = (0x4d4e4f50 & parts[3])
    return r0 ^ r1 ^ r2 ^ r3 ^ r4



def generate_flag():
    solver = claripy.Solver()

    parts = []
    flag = claripy.BVS('flag', 4 * 4 * 8)
    for i in range(4):
        part = flag.get_bytes(i * 4, 4)
        for j in range(4):
            solver.add(0x21 <= part.get_byte(j))
            solver.add(part.get_byte(j) <= 0x7e)

    r0 = (0x41424344 & flag.get_bytes(0 * 4, 4)) ^ 0x41404044
    r1 = (0x45464748 & flag.get_bytes(1 * 4, 4)) ^ 0x41044748
    r2 = (0x494a4b4c & flag.get_bytes(2 * 4, 4)) ^ 0x494a404c
    r3 = 0x4d424340
    r4 = (0x4d4e4f50 & flag.get_bytes(3 * 4, 4))

    solver.add((r0 ^ r1 ^ r2 ^ r3 ^ r4) == 0)

    flag_str = solver.eval(flag, 1)[0].to_bytes(16, byteorder='big').decode()
    output = b''
    # translate flag_str to 4 parts in little endian
    for i in range(4):
        tmp = flag_str[i*4:(i+1)*4].encode()
        output += tmp[::-1]  # reverse byte order

    assert confirm(output) == 0
    print(output.decode())


if __name__ == '__main__':
    generate_flag()
