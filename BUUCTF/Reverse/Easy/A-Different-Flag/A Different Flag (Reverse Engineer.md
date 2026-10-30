# CTF Write-up: A Different Flag (Reverse Engineering)

## 📝 Challenge Description
* **Category:** Reverse Engineering
* **Difficulty:** Easy-Medium
* **Platform/Context:** CTF Binary Analysis
* **Target Artifact:** `flag.exe` (x86_64 Windows PE Executable)
**Author:** Gantosay
---

## 🔍 Phase 1: Information Gathering & Triage
I started the analysis inside a **Ubuntu Linux** environment. First, I determine the core properties of the binary using the native `file` command:

```bash
file flag.exe
```
This confirms that the target is a  PE (Portable Executable)** binary. To inspect user-readable strings embedded inside the executable, I use `strings` or the text scanning functionality inside **Rizin**:

```radare2
iz ~ flag
```
**Output:**
```text
0x0000146c 0x0040306c  37   38 .rdata        ascii   \nok, the order you enter is the flag!
```

This dynamic tip reveals two critical facts:
1. The executable expects sequential inputs from the user.
2. The exact sequence (order) of correct inputs functions as the flag itself.

---

## 💻 Phase 2: Static Analysis & Memory Carving
I invoke Rizin to perform automated analysis (`rizin -A flag.exe`) and list the tracked functions using `afl` (Analyze Functions List). The main user-logic lives at `dbg.main` located at address `0x00401334`.

```radare2
s main
pdf
```

### 🧠 Reverse Engineering the Disassembly:
Upon analyzing the control flow structure of the assembly code, I identify three distinct operational building blocks:

1. **The Grid Initialization (`0x00401359`):**
   The binary loads a static reference from the data segment:
   ```assembly
   mov ebx, str.11110100001010000101111  ; "*11110100001010000101111#"
   ```
   By running a memory dump via `p8 25 @ 0x402000`, we extract the raw bytes:
   ```text
   2a 31 31 31 31 30 31 30 30 30 30 31 30 31 30 30 30 30 31 30 31 31 31 31 23
   ```
   Translating these ASCII hex characters results in a 25-character matrix string:  
   `*11110100001010000101111#`

2. **Movement Routing (`0x004013be - 0x00401409`):**
   The application displays a menu (`1 up`, `2 down`, `3 left`, `4 right`) and tracks an input variable.
   * Selecting **1** decreases the vertical coordinate axis tracker (`dec dword [var_20h]`).
   * Selecting **2** increases the vertical coordinate axis tracker (`inc dword [var_20h]`).
   * Selecting **3** decreases the horizontal coordinate axis tracker (`dec dword [var_1ch]`).
   * Selecting **4** increases the horizontal coordinate axis tracker (`inc dword [var_1ch]`).

3. **Validation & Bound Constraints (`0x00401451 - 0x0040149b`):**
   The program computes the position dynamically using an array-offset matrix formula: `Index = (Row * 5) + Column`.
   * **Collision Check:** It inspects if the character equals `0x31` (`'1'`). If true, it triggers a failure branch via `sym._exit`.
   * **Winning Check:** It checks if the destination tile matches `0x23` (`'#'`). If true, it falls out of the loop to print the success flag prompt.

---

## 🛠️ Phase 3: Original Source Code Reconstruction (C)
By mapping out the exact stack behaviors, string placements, and mathematical calculations extracted from the disassembly, the original high-level logic can be accurately reconstructed in **C**:

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    // 5x5 Maze Matrix stored as a linear array
    char maze[] = "*11110100001010000101111#";
    
    int row = 0;    // Tracks the vertical coordinate
    int col = 0;    // Tracks the horizontal coordinate
    int choice;

    while (1) {
        printf("you can choose one action to execute\n");
        printf("1 up\n2 down\n3 left\n4 right\n: ");
        
        if (scanf("%d", &choice) != 1) {
            exit(1);
        }

        // Apply spatial translations
        if (choice == 1) row--;
        else if (choice == 2) row++;
        else if (choice == 3) col--;
        else if (choice == 4) col++;
        else exit(1);

        // Boundary constraint checking
        if (row < 0 || row > 4 || col < 0 || col > 4) {
            exit(1);
        }

        // Matrix indexing formula: (Row * Width) + Column
        int current_position = (row * 5) + col;
        char current_tile = maze[current_position];

        // Hit a wall block ('1')
        if (current_tile == '1') {
            exit(1);
        }

        // Target goal reached ('#')
        if (current_tile == '#') {
            printf("ok, the order you enter is the flag!\n");
            break;
        }
    }
    return 0;
}
```

---

## 🤖 Phase 4: Algorithmic Automated Solver (Python BFS)
To dynamically solve the extracted memory matrix without manually guessing steps, I map the 25 extracted ASCII bytes into a spatial 2D array and solve it automatically using a **Breadth-First Search (BFS)** algorithm in Python:

```python
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
```

### Visual Representation of the Maze Solution:
```text
  [Start]
     ↓
   *  1  1  1  1
   ↓
   0  1  0  0  0
   ↓     ↑     
   0  1  0  1  0
   ↳  →  ↑  1  0
   1  1  1  1  #  ← [Goal]
```

---

