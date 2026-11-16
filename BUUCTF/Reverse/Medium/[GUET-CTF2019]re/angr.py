#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# [GUET-CTF 2019] re - Method 3: Symbolic Execution with angr
#
# Instead of symbolically executing from the binary's entry point (which
# would drag angr through the entire statically-linked libc startup path
# and scanf()'s own internals, causing severe state explosion), this script
# starts execution directly at check()'s first instruction. A symbolic
# 32-byte buffer is injected into memory, rdi is pointed at it (matching
# check()'s calling convention exactly), and a sentinel return address is
# pushed so a successful "return with eax == 1" is easy to detect as the
# exploration's goal state.

import angr
import claripy

BINARY_PATH = "./re"
CHECK_FUNCTION_ADDR = 0x4009ae
FLAG_LENGTH = 32

# A sentinel return address: chosen specifically because it's extremely
# unlikely to collide with any real address check() might otherwise jump to,
# making it a safe, unambiguous marker for "check() has just returned".
SENTINEL_RETURN_ADDR = 0xdeadbeef

# An arbitrary, unused region of the address space to hold our symbolic
# input buffer -- chosen to avoid colliding with the binary's own mapped
# segments, the stack, or the heap.
SYMBOLIC_BUFFER_ADDR = 0x700000

# A stack pointer value placed well within angr's default stack region,
# leaving plenty of room both above and below for check()'s own local
# frame and our pushed return address.
INITIAL_STACK_POINTER = 0x7fff0000


def build_initial_state(project):
    """
    Construct a blank_state seeded at check()'s entry point, with:
      - rdi pointing at a fresh symbolic buffer (the flag pointer argument)
      - rsp set to a safe stack location
      - our sentinel return address pushed, so check()'s own `ret` lands
        exactly where our exploration's find/avoid conditions expect it
    """
    flag_byte_vars = [claripy.BVS(f"flag_byte_{i}", 8) for i in range(FLAG_LENGTH)]
    symbolic_flag = claripy.Concat(*flag_byte_vars)

    state = project.factory.blank_state(addr=CHECK_FUNCTION_ADDR)

    state.regs.rdi = SYMBOLIC_BUFFER_ADDR
    state.regs.rsp = INITIAL_STACK_POINTER
    state.stack_push(SENTINEL_RETURN_ADDR)

    state.memory.store(SYMBOLIC_BUFFER_ADDR, symbolic_flag)

    # Restrict every symbolic byte to printable ASCII up front -- this
    # mirrors the real flag format and substantially narrows the search
    # space angr has to explore, compared to leaving all 256 byte values
    # open for every position.
    for byte_var in flag_byte_vars:
        state.solver.add(byte_var >= 0x20)
        state.solver.add(byte_var <= 0x7e)

    return state, symbolic_flag


def reached_success(state):
    """True once execution has returned to our sentinel with eax == 1."""
    return state.addr == SENTINEL_RETURN_ADDR and state.solver.eval(state.regs.eax) == 1


def reached_failure(state):
    """True once execution has returned to our sentinel with eax == 0."""
    return state.addr == SENTINEL_RETURN_ADDR and state.solver.eval(state.regs.eax) == 0


def main():
    project = angr.Project(BINARY_PATH, auto_load_libs=False)

    state, symbolic_flag = build_initial_state(project)

    simulation = project.factory.simulation_manager(state)

    simulation.explore(find=reached_success, avoid=reached_failure)

    if not simulation.found:
        print("[-] No satisfying path found.")
        return

    found_state = simulation.found[0]
    solution = found_state.solver.eval(symbolic_flag, cast_to=bytes)

    print("[+] angr found a satisfying input:")
    print(solution.decode(errors="replace"))


if __name__ == "__main__":
    main()