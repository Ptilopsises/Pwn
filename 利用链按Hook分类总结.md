# 堆相关利用链按 Hook 分类总结

本文基于 `堆相关.md` 中已经写到的利用链与例题进行归类，只讨论“最终控制程序流时是否依赖 `__malloc_hook / __free_hook`”。

## 一、需要 malloc_hook 或 free_hook 控制程序流的利用链

### 1) malloc_hook 劫持链

- 典型思路：通过 fastbin/tcache poisoning 把可写位置引到 __malloc_hook，写入 one_gadget 或其他可执行地址，随后触发 malloc 进入劫持地址。
- 文中对应：
- malloc hook 章节的通用思路
- 例题 [HNCTF_2022_WEEK4]ez_uaf：最终改写 __malloc_hook 为 one_gadget，触发 malloc 拿 shell
- 例题 SWPUCTF_2019_p1KkHeap：最终把 malloc_hook 指向 shellcode 地址，通过再次分配触发执行

### 2) free_hook 劫持链

- 典型思路：把 __free_hook 改成 system 或 setcontext+53 等地址，随后调用 free(目标指针) 触发控制流。
- 文中对应：
- free_hook 章节的通用思路（如写 system，再 free('/bin/sh')）
- setcontext 章节：先把 __free_hook 改为 setcontext+53，再 free 一个伪造上下文的堆块，完成栈迁移并执行 ROP/ORW

## 二、不需要 malloc_hook / free_hook 的利用链

### 1) UAF 覆盖对象内函数指针（BuuCTF-hitcontraining_uaf）

- 控制流方式：
- 利用 UAF + 堆复用，拿到原 note 结构体位置
- 覆盖 note 结构里的函数指针（原 print_note_content）为目标函数地址（如 magic）
- 触发 print_note 时走到被改写后的函数指针
- 本质：不是改 hook，而是改“程序对象自己的回调/函数指针”。

### 2) Fastbin Attack + GOT 劫持（[ZJCTF 2019]EasyHeap）

- 控制流方式：
- fastbin attack 拿到伪造块，改写 heaparray 指针，进一步实现任意地址写
- 把 free@GOT 改成 system@PLT
- 当程序执行 free(chunk_with_/bin/sh) 时，实际变成调用 system('/bin/sh')
- 本质：通过 GOT 表改写函数解析结果，不依赖 malloc_hook/free_hook。

### 3) Unsorted Bin Attack 逻辑劫持（hitcontraining_magicheap）

- 控制流方式：
- 利用 unsorted bin attack 的写原语，把 magic 改到阈值以上
- 触发菜单分支进入隐藏功能（l33t）获得 shell
- 本质：主要是“关键全局变量改值 -> 程序走到危险分支”，不是 hook 劫持。

### 4) IO_FILE / vtable 劫持（[CISCN 2022 华东北]duck）

- 控制流方式：
- 在 glibc 2.34 场景下不使用 hook
- 通过堆利用拿到写原语，改写 __libc_IO_vtables 区域中目标跳表槽位（如 _IO_file_jumps 某函数指针）
- 触发对应 stdio 操作，让 FILE 虚调用跳到 one_gadget
- 本质：劫持的是 FILE 虚函数调用链（vtable dispatch），不是 malloc/free hook。

## 三、速查表

| 利用链 | 是否依赖 malloc_hook/free_hook | 程序流控制点 |
| --- | --- | --- |
| malloc_hook 劫持（通用、ez_uaf、p1KkHeap 结尾） | 需要 | __malloc_hook -> one_gadget/shellcode |
| free_hook 劫持（通用） | 需要 | __free_hook -> system |
| free_hook + setcontext | 需要 | __free_hook -> setcontext+53，再栈迁移到 ROP |
| UAF 覆盖 note 函数指针（hacknote） | 不需要 | 覆盖对象内函数指针 |
| fastbin + GOT 劫持（EasyHeap） | 不需要 | free@GOT -> system@PLT |
| unsorted bin 改 magic（magicheap） | 不需要 | 关键变量改值触发危险逻辑 |
| IO_FILE/vtable 劫持（duck） | 不需要 | _IO_file_jumps 对应槽位函数指针 |

## 四、一句话结论

你这份文档里，依赖 hook 的主要是 malloc_hook/free_hook 直接劫持链（含 free_hook+setcontext 变体）；不依赖 hook 的主线是三类：对象函数指针覆盖、GOT 劫持、IO_FILE 虚表劫持，外加一种“改关键变量触发分支”的逻辑劫持。
