from collections import deque

s = "*******+********* ******    ****   ******* **F******    **************"
W = 10
grid = [s[i:i+W] for i in range(0, len(s), W)]
R = len(grid)

for r in range(R):
    for c in range(len(grid[r])):
        if grid[r][c] == '+': start = (r, c)
        if grid[r][c] == 'F': goal = (r, c)

print("start", start, "goal", goal)

moves = {'w': (-1, 0), 's': (1, 0), 'a': (0, -1), 'd': (0, 1)}
q = deque([(start, "")])
seen = {start}
while q:
    (r, c), path = q.popleft()
    if (r, c) == goal:
        print(path, len(path))
        break
    for k, (dr, dc) in moves.items():
        nr, nc = r + dr, c + dc
        if (0 <= nr < R and 0 <= nc < len(grid[nr])
                and grid[nr][nc] != '*' and (nr, nc) not in seen):
            seen.add((nr, nc))
            q.append(((nr, nc), path + k))
