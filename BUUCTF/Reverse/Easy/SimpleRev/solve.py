def solve_perfect_simplerev():
    target_text = "killshadow"
    key = "adsfkndcls"
    v5 = len(key)
    
    # 🔒 The Critical Fix: v3 is already 10 after the first key loop!
    v3 = 10
    
    flag = []
    
    for i in range(len(target_text)):
        t_char = ord(target_text[i])
        k_char = ord(key[v3 % v5])
        
        # Check all possible valid characters (A-Z and a-z)
        found = False
        for v1 in range(65, 123):
            # Exclude non-alpha chars between Z (90) and a (97)
            if 90 < v1 < 97:
                continue
                
            # Replicating the exact calculation logic
            if (v1 - 39 - k_char + 97) % 26 + 97 == t_char:
                flag.append(chr(v1))
                found = True
                break
        v3 += 1

    print("═" * 50)
    print(f"RAW RECOVERED TEXT: {''.join(flag)}")
    print("═" * 50)

solve_perfect_simplerev()

