#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# picoCTF - Matrix (Gantoay)

import sys
from collections import deque

WALL   = bytes([0x81, 0xfb, 0x00, 0x30])
OPEN   = bytes([0x30, 0x00, 0x00, 0x00])
HEALTH = bytes([0x81, 0x7f, 0x05, 0x30])
HAZARD = bytes([0x81, 0x74, 0x05, 0x30])
EXIT   = bytes([0x81, 0x85, 0x05, 0x30])

SYMBOL_OF = {WALL: "#", OPEN: ".", HEALTH: "+", HAZARD: "-", EXIT: "E"}

GRID_SIZE = 16
CELL_SIZE = 4
TABLE_SIZE = GRID_SIZE * GRID_SIZE * CELL_SIZE  # 1024


def is_clean_table(region: bytes) -> bool:
    if len(region) != TABLE_SIZE:
        return False
    for i in range(0, TABLE_SIZE, CELL_SIZE):
        if region[i:i+CELL_SIZE] not in SYMBOL_OF:
            return False
    return True


def find_table_start(data: bytes) -> int:
    """
    Find every EXIT occurrence (should be exactly one, but don't assume it),
    then for each one, try a small window of nearby candidate table-start
    offsets (not just exit_offset - 255*4) until a fully clean 256-cell
    table is found. This makes the search robust to the table's cell COUNT
    before the exit differing slightly, instead of hardcoding "255 cells
    before the exit" as the only possibility.
    """
    exit_offsets = []
    start = 0
    while True:
        i = data.find(EXIT, start)
        if i == -1:
            break
        exit_offsets.append(i)
        start = i + 1

    if not exit_offsets:
        raise ValueError("No EXIT cell pattern found anywhere in the file.")

    for exit_offset in exit_offsets:
        table_end = exit_offset + CELL_SIZE
        # Try the exit as cell index 255, 254, 253... down to 240, in case
        # of a few bytes of drift either way.
        for cells_before_exit in range(255, 239, -1):
            candidate_start = table_end - (cells_before_exit + 1) * CELL_SIZE
            if candidate_start < 0:
                continue
            region = data[candidate_start:candidate_start + TABLE_SIZE]
            if is_clean_table(region):
                return candidate_start

    raise ValueError(
        "Could not find a clean 256-cell table near any EXIT occurrence. "
        f"EXIT found at file offsets: {[hex(o) for o in exit_offsets]}"
    )


def extract_grid(data: bytes, table_start: int):
    region = data[table_start:table_start + TABLE_SIZE]
    grid = []
    for row in range(GRID_SIZE):
        row_cells = []
        for col in range(GRID_SIZE):
            idx = row * GRID_SIZE + col
            cell = region[idx*CELL_SIZE : idx*CELL_SIZE + CELL_SIZE]
            row_cells.append(SYMBOL_OF[cell])
        grid.append(row_cells)
    return grid


def solve_maze(grid, start=(1, 1, 0)):
    queue = deque([(start, "")])
    visited = {start}
    moves = [(-1, 0, "u"), (1, 0, "d"), (0, -1, "l"), (0, 1, "r")]

    while queue:
        (row, col, hp), path = queue.popleft()
        if grid[row][col] == "E":
            return path
        for d_row, d_col, command in moves:
            n_row, n_col = row + d_row, col + d_col
            if not (0 <= n_row < GRID_SIZE and 0 <= n_col < GRID_SIZE):
                continue
            cell = grid[n_row][n_col]
            if cell == "#":
                continue
            n_hp = hp + (1 if cell == "+" else -1 if cell == "-" else 0)
            if n_hp < 0:
                continue
            state = (n_row, n_col, n_hp)
            if state not in visited:
                visited.add(state)
                queue.append((state, path + command))
    return None


def main():
    binary_path = sys.argv[1] if len(sys.argv) > 1 else "matrix"
    with open(binary_path, "rb") as f:
        data = f.read()

    table_start = find_table_start(data)
    print(f"[+] Maze table verified at file offset {table_start:#x}", file=sys.stderr)

    grid = extract_grid(data, table_start)

    print("=== EXTRACTED 16x16 MAZE ===", file=sys.stderr)
    for row_index, row in enumerate(grid):
        print(f"{row_index:02d}: " + " ".join(row), file=sys.stderr)

    path = solve_maze(grid)
    if path is None:
        print("[-] No valid path found.", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Solution path ({len(path)} moves):", file=sys.stderr)
    print(path)  # ONLY this goes to stdout, so `| tail -n 1 | nc ...` stays clean


if __name__ == "__main__":
    main()
