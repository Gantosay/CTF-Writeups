; ============================================================
; CallbackVM/1 -- deterministic offline listing
; ============================================================

token.transferFrom:
    ENTER 3
    TOKEN_XFER [arg0], [arg1], [arg2]
    LEAVE
    RET

Vault.deposit:
    ENTER 1
    PUSH [arg0]
    GT 0
    JZ deposit_bad

    TOKEN_XFER caller, self, [arg0]     ; <-- hook fires here, credits once

    LOADM caller                        ; <-- SECOND credit begins here (the bug)
    PUSH [arg0]
    ADD
    STOREM caller

    EMIT DepositCredited(caller, [arg0])
    LEAVE
    RET

deposit_bad:
    REVERT "amount must be positive"

Vault.onRWDReceived:
    ENTER 3
    LOADM [arg0]
    PUSH [arg1]
    ADD
    STOREM [arg0]                        ; <-- FIRST credit happens here
    LEAVE
    RET

Vault.withdrawAll:
    ENTER 0
    LOAD 2
    JZ withdraw_unlocked
    REVERT "reentrancy lock"

withdraw_unlocked:
    PUSH 1
    STORE 2

    LOADM caller
    STORE 3
    PUSH 0
    STOREM caller                        ; credit zeroed BEFORE the transfer -- correct ordering

    TOKEN_XFER self, caller, [S3]

    PUSH 0
    STORE 2
    EMIT Withdrawal(caller, [S3])
    LEAVE
    RET

main:
    ENTER 0
    PUSH 11
    STORE T0
main_loop:
    LOAD T0
    ISZERO
    JZ main_done

    PUSH 137
    XCALL 0xa77ac.deposit

    XCALL 0xa77ac.withdrawAll

    LOAD T0
    PUSH 1
    SUB
    STORE T0
    JMP main_loop

main_done:
    HALT