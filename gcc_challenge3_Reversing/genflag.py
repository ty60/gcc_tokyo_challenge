import claripy


def generate_flag():
    solver = claripy.Solver()

    parts = []
    for i in range(4):
        part = claripy.BVS('flag_{}'.format(i), 4 * 8)
        for j in range(4):
            solver.add(0x21 <= part.get_byte(j))
            solver.add(part.get_byte(j) <= 0x7e)
        parts.append(part)

    r0 = (0x41424344 & parts[0]) ^ 0x41404044
    r1 = (0x45464748 & parts[1]) ^ 0x41044748
    r2 = (0x494a4b4c & parts[2]) ^ 0x494a404c
    r3 = 0x4d424340 
    r4 = (0x4d4e4f50 & parts[3])

    solver.add((r0 ^ r1 ^ r2 ^ r3 ^ r4) == 0)
    flag = ""
    for i in range(4):
        # output in big endian.
        # the flag is going to be read as a string.
        flag += solver.eval(parts[i], 1)[0].to_bytes(4, byteorder='big').decode()
    print(flag)


if __name__ == '__main__':
    generate_flag()
