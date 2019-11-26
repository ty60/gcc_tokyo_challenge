import angr
import claripy
import json

from pathlib import Path

def should_stop(proj, state, stop_by):
    bb = proj.factory.block(state.solver.eval(state.regs.rip))
    return bb.addr <= stop_by < bb.addr + bb.size


def run_stopping_by(proj, state, stop_by):
    simgr = proj.factory.simgr(state)

    while simgr.active:
        simgr = simgr.step()
        simgr.move(from_stash='active', to_stash='stops', \
                filter_func=lambda s: should_stop(proj, s, stop_by))
    return simgr.stops


FILE_NAME = '/tmp/input.bin'
BASE_ADDR = 0x400000
def crack(binpath):
    proj = angr.Project(binpath)

    argv = [binpath, FILE_NAME]
    state = proj.factory.full_init_state(args=argv)

    # TODO: Maybe I shouldn't spcify concrete size.
    # Should size also be an data to solve dynamically?
    content = claripy.BVS('input', 200 * 8)
    input_file = angr.SimFile(FILE_NAME, content=content)
    # input_file = angr.SimFile(FILE_NAME, size=200)
    state.fs.insert(FILE_NAME, input_file)

    simgr = proj.factory.simgr(state)
    # run to call to function crash
    stops = run_stopping_by(proj, state, BASE_ADDR+0xa4a)
    simgr.run()

    if (len(stops) > 0):
        return (c \
                for s in stops \
                for c in s.solver.eval_upto(content, 1, cast_to=bytes))
    else:
        raise Exception("Not found")


if __name__ == '__main__':
    crash_inputs = crack('./simple_linter')
    p = Path("./angr_crashes")
    for i, ci in enumerate(crash_inputs):
        with (p / '{}.bin'.format(i)).open('wb') as f:
            f.write(ci)
    # print(json.dumps(list(crash_inputs), indent=4))
