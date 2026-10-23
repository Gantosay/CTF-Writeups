target = "Qsw3sj_lz4_Ujw@l"
flag_chars = ""

for char in target:
    
    found = False
    for x in range(32, 127):
        temp = x
        if 64 < temp <= 90:    
            temp = (temp - 51) % 26 + 65
        elif 96 < temp <= 122:  
            temp = (temp - 79) % 26 + 97
            
        if chr(temp) == char:
            flag_chars += chr(x)
            found = True
            break
    if not found:
        flag_chars += char

print(f"Inside bracket: {flag_chars}")
