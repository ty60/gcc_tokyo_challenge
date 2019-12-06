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
