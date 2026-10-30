#!/usr/bin/env python3
from collections import deque

def solve_ctf_maze():
    # Carved string from 0x402000
    maze_raw = "*11110100001010000101111#"
    
    # Restructure into a true 5x5 matrix layout
    grid = [list(maze_raw[i:i+5]) for i in range(0, 25, 5)]
    
    # Movement routing vectors paired to user commands
    move_vectors = {
        (-1, 0): '1',  # Up
        (1, 0):  '2',  # Down
        (0, -1): '3',  # Left
        (0, 1):  '4'   # Right
    }
    
    # Define start node coordinates (*)
    start_r, start_c = 0, 0
    
    # Queue structure: (row, col, path_string)
    bfs_queue = deque([(start_r, start_c, "")])
    visited_nodes = set([(start_r, start_c)])
    
    while bfs_queue:
        curr_r, curr_c, dynamic_path = bfs_queue.popleft()
        
        # Check if current tile state is target node (#)
        if grid[curr_r][curr_c] == '#':
            print("[+] Target Route Discovered Automatically!")
            print(f"[+] Decrypted Flag: flag{{{dynamic_path}}}")
            return
            
        # Scan prospective spatial transitions
        for (delta_r, delta_c), cmd in move_vectors.items():
            next_r, next_c = curr_r + delta_r, curr_c + delta_c
            
            # Validation gates: boundary limits, wall blocks, and historical nodes
            if 0 <= next_r < 5 and 0 <= next_c < 5:
                if grid[next_r][next_c] != '1' and (next_r, next_c) not in visited_nodes:
                    visited_nodes.add((next_r, next_c))
                    bfs_queue.append((next_r, next_c, dynamic_path + cmd))

if __name__ == "__main__":
    solve_ctf_maze()