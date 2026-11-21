#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# CallbackVM Simulator -- Callback Credit Vault Challenge-Gantosay
#
# Faithfully implements TOKEN_XFER's exact semantics, including the
# synchronous, in-the-middle-of-the-call hook invocation described in the
# asm listing's own header comment. The double-credit bug in deposit() is
# deliberately left exactly as written in the asm -- this simulator exists
# to REPRODUCE the challenge's real behavior, not to silently correct it.

A = "0xa77ac"      # attacker
V = "0x7a1117"     # vault (has the registered hook)
H = "0x40a57"      # honest, uninvolved account

RWD = {
    A: 1234,
    V: 4096,
    H: 5000,
}

credit = {
    A: 0,
    H: 4096,
}

lock = 0

# Mirrors the asm's own hook_registry: only the Vault's address has a
# registered callback. Every other TOKEN_XFER recipient is inert.
HOOK_REGISTRY = {
    V: "onRWDReceived",
}


def token_xfer(frm, to, amt):
    """
    Exactly mirrors TOKEN_XFER's documented semantics:
      require RWD[frm] >= amt; subtract; add;
      if hook[to] exists, invoke it with (frm, amt, data) BEFORE returning;
      then return to the caller instruction.
    """
    global RWD

    if RWD[frm] < amt:
        raise RuntimeError(
            f"insufficient balance: {frm} has {RWD[frm]}, needs {amt}"
        )

    RWD[frm] -= amt
    RWD[to] += amt

    if to in HOOK_REGISTRY:
        on_rwd_received(frm, amt)


def on_rwd_received(frm, amt):
    """Vault.onRWDReceived: credit-on-receive, exactly as disassembled."""
    credit[frm] = credit.get(frm, 0) + amt
    print(f"  [HOOK]  credit[{frm}] += {amt}  ->  {credit[frm]}")


def deposit(caller, amt):
    """
    Vault.deposit, including the double-accounting bug exactly as written:
    TOKEN_XFER runs (triggering the hook's credit update above), and THEN
    this function performs its own, independent credit update on top of it.
    """
    print(f"\n=== deposit({amt}) from {caller} ===")

    if amt <= 0:
        raise RuntimeError("amount must be positive")

    print(f"  TOKEN_XFER {caller} -> {V}  amount={amt}")
    token_xfer(caller, V, amt)

    # The second, buggy credit -- left intentionally exactly as disassembled.
    credit[caller] = credit.get(caller, 0) + amt
    print(f"  [DEPOSIT] credit[{caller}] += {amt}  ->  {credit[caller]}")
    print(f"  RWD -> attacker={RWD[A]} | vault={RWD[V]}")


def withdraw_all(caller):
    """Vault.withdrawAll: correct checks-effects-interactions, as disassembled."""
    global lock

    print(f"\n=== withdrawAll() from {caller} ===")

    if lock != 0:
        raise RuntimeError("reentrancy lock")

    lock = 1
    amt = credit.get(caller, 0)
    credit[caller] = 0
    print(f"  credit taken = {amt} | credit reset to 0 | lock=1")

    print(f"  TOKEN_XFER {V} -> {caller}  amount={amt}")
    token_xfer(V, caller, amt)

    lock = 0
    print(f"  lock=0")
    print(f"  RWD -> attacker={RWD[A]} | vault={RWD[V]}")


def run_script(cycles, deposit_amount):
    print("=" * 50)
    print("START STATE")
    print(f"RWD     -> attacker={RWD[A]} | vault={RWD[V]} | honest={RWD[H]}")
    print(f"credit  -> attacker={credit[A]} | honest={credit[H]}")
    print(f"lock    -> {lock}")
    print("=" * 50)

    for i in range(1, cycles + 1):
        print(f"\n########## Cycle {i} ##########")
        deposit(A, deposit_amount)
        withdraw_all(A)

    print("\n" + "=" * 50)
    print("FINAL STATE")
    print(f"RWD[attacker] = {RWD[A]:6d}   hex: {RWD[A]:016x}")
    print(f"RWD[vault]    = {RWD[V]:6d}   hex: {RWD[V]:016x}")
    print(f"RWD[honest]   = {RWD[H]}")
    print(f"credit[attacker] = {credit[A]}")
    print(f"credit[honest]   = {credit[H]}")
    print(f"lock             = {lock}")
    print("=" * 50)

    print(f"\nFLAG = flag{{{RWD[V]:016x}{RWD[A]:016x}}}")


if __name__ == "__main__":
    run_script(cycles=11, deposit_amount=137)
