#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
浮点数在内存中的表示查看工具 (IEEE 754)
支持：float16(手写转换)、float32、float64
输出：字节序(hex)、二进制、拆分后的符号位/指数/尾数字段，解释值类别。

用法示例 (PowerShell)：
  python MISC/py代码/float_mem.py 3.1415926
  python MISC/py代码/float_mem.py 0.1 --prec f32
  python MISC/py代码/float_mem.py -0.0 --prec f64
  python MISC/py代码/float_mem.py nan
  python MISC/py代码/float_mem.py 1.5 --prec f16
  python MISC/py代码/float_mem.py 3.14 --prec f32 --endian big

参数：
  value:     可以写 1.23 / -0.0 / inf / -inf / nan
  --prec:    f16 / f32 / f64   (默认 f64，等同于 Python float)
  --endian:  little / big      (显示打包字节序，默认 little)
"""

import struct
import math
import argparse
from typing import Literal, Dict

Precision = Literal['f16', 'f32', 'f64']

def classify_float(sign: int, exponent_raw: int, fraction_raw: int, exp_bits: int, frac_bits: int):
    """根据 IEEE754 规则分类"""
    bias = (1 << (exp_bits - 1)) - 1
    if exponent_raw == (1 << exp_bits) - 1:
        if fraction_raw == 0:
            return "Infinity" if sign == 0 else "-Infinity"
        else:
            return "NaN"
    if exponent_raw == 0:
        if fraction_raw == 0:
            return "Zero" if sign == 0 else "-Zero"
        else:
            return "Subnormal"
    return "Normal"

def pack_float32(value: float, endian: str) -> bytes:
    fmt = '<f' if endian == 'little' else '>f'
    return struct.pack(fmt, value)

def pack_float64(value: float, endian: str) -> bytes:
    fmt = '<d' if endian == 'little' else '>d'
    return struct.pack(fmt, value)

def float_to_bits(data: bytes) -> str:
    return ''.join(f'{b:08b}' for b in data)

# ---- float16 手动转换（不依赖 numpy）----
def float_to_float16_bits(value: float) -> int:
    """
    将 Python float(64位) 转成 IEEE754 binary16 的 16bit 整数表示
    参考：IEEE 754 半精度：1 符号 + 5 指数 + 10 fraction
    """
    # 特殊值直接处理
    if math.isnan(value):
        return 0x7E01  # 一个典型的 quiet NaN（也可以任意非零尾数）
    if math.isinf(value):
        return 0x7C00 if value > 0 else 0xFC00
    # 获取 sign
    sign = 0
    if math.copysign(1.0, value) < 0:
        sign = 1
        value = -value
    if value == 0.0:
        return sign << 15  # +0 或 -0
    # 正常数处理
    mant, exp = math.frexp(value)  # value = mant * 2^(exp), mant in [0.5,1)
    # 目标 exponent = exp + bias - 1 (因为 mantin [0.5,1))
    # half bias = 15
    exp_unbiased = exp
    exp_half = exp_unbiased + 14  # 这里 -1 + bias = -1 + 15 = 14
    # 正常范围：1..30 (除去全0与全1)
    if exp_half <= 0:
        # 次正规数 (subnormal)
        # 把 mant * 2^(exp_unbiased) 重新转成 2^( -14 ) * fraction
        # value = mant * 2^(exp_unbiased) = fraction * 2^(-14)
        # fraction = value / 2^(-14)
        fraction = value / (2 ** -14)
        frac_raw = int(fraction + 0.5)  # 四舍五入
        # 移除超过10bit的部分
        if frac_raw >= (1 << 10):
            frac_raw = (1 << 10) - 1
        return (sign << 15) | frac_raw
    elif exp_half >= 31:
        # 溢出 -> Infinity
        return (sign << 15) | 0x7C00
    else:
        # 正常数
        # mant = m / 2  (因为 mant in [0.5,1), 想要得到 1.x 形式的尾数)
        mant_norm = (mant * 2) - 1.0
        frac_raw = int(mant_norm * (1 << 10) + 0.5)
        if frac_raw == (1 << 10):
            # 进位导致尾数溢出，需要指数+1
            frac_raw = 0
            exp_half += 1
            if exp_half >= 31:
                return (sign << 15) | 0x7C00  # Infinity
        return (sign << 15) | (exp_half << 10) | frac_raw

def float16_pack(value: float, endian: str) -> bytes:
    bits16 = float_to_float16_bits(value)
    b = bits16.to_bytes(2, byteorder='big')
    if endian == 'little':
        b = b[::-1]
    return b

def decode_fields(bitstr: str, exp_bits: int, frac_bits: int):
    sign = int(bitstr[0], 2)
    exponent_raw = int(bitstr[1:1+exp_bits], 2)
    fraction_raw = int(bitstr[1+exp_bits:], 2)
    return sign, exponent_raw, fraction_raw

def explain(value: float, precision: Precision, endian: str) -> Dict:
    if precision == 'f16':
        data = float16_pack(value, endian)
        exp_bits, frac_bits = 5, 10
    elif precision == 'f32':
        data = pack_float32(value, endian)
        exp_bits, frac_bits = 8, 23
    else:
        data = pack_float64(value, endian)
        exp_bits, frac_bits = 11, 52

    bitstr = float_to_bits(data)
    sign, exponent_raw, fraction_raw = decode_fields(bitstr, exp_bits, frac_bits)
    bias = (1 << (exp_bits - 1)) - 1
    classification = classify_float(sign, exponent_raw, fraction_raw, exp_bits, frac_bits)

    # 计算实际指数与尾数（仅 Normal / Subnormal）
    if exponent_raw == 0:
        if fraction_raw == 0:
            exponent_val = None
            mantissa_val = 0.0
        else:
            exponent_val = 1 - bias
            mantissa_val = fraction_raw / (1 << frac_bits)
    elif exponent_raw == (1 << exp_bits) - 1:
        exponent_val = None
        mantissa_val = None
    else:
        exponent_val = exponent_raw - bias
        mantissa_val = 1 + fraction_raw / (1 << frac_bits)

    return {
        "input": value,
        "precision": precision,
        "endian": endian,
        "bytes_hex_ordered": ' '.join(f'{b:02X}' for b in data),  # 按内存顺序
        "raw_bytes": data,
        "bitstring": bitstr,
        "fields": {
            "sign_bit": sign,
            "exponent_raw": exponent_raw,
            "fraction_raw": fraction_raw,
            "exponent_bits": exp_bits,
            "fraction_bits": frac_bits,
            "bias": bias
        },
        "decoded": {
            "classification": classification,
            "exponent_value": exponent_val,
            "mantissa_value": mantissa_val,
            "reconstructed (approx)": (
                None if mantissa_val is None or exponent_val is None
                else ((-1) ** sign) * mantissa_val * (2 ** exponent_val)
            )
        }
    }

def pretty_print(info: Dict):
    print(f"输入值: {info['input']}  (Python解析后: {info['input']!r})")
    print(f"精度: {info['precision']}  字节序: {info['endian']}")
    print(f"内存字节 (低地址→高地址): {info['bytes_hex_ordered']}")
    print(f"二进制位串: {info['bitstring']}")
    f = info['fields']
    exp_bits = f["exponent_bits"]
    frac_bits = f["fraction_bits"]
    bitstr = info["bitstring"]
    print(f"  符号位 : {bitstr[0]}")
    print(f"  指数位 : {bitstr[1:1+exp_bits]}  (raw={f['exponent_raw']}, bias={f['bias']})")
    print(f"  尾数位 : {bitstr[1+exp_bits:]}  (raw={f['fraction_raw']})")

    d = info['decoded']
    print(f"分类: {d['classification']}")
    if d['exponent_value'] is not None:
        print(f"实际指数 = {d['exponent_value']}")
    if d['mantissa_value'] is not None:
        print(f"实际尾数(含隐含位) = {d['mantissa_value']}")
    if d['reconstructed (approx'] is not None:
        pass  # 防止误键
    if d['reconstructed (approx)'] is not None:
        print(f"按字段重建近似值 = {d['reconstructed (approx)']}")

def parse_value(s: str) -> float:
    sl = s.lower()
    if sl in ('nan', '+nan', '-nan'):
        return float('nan')
    if sl in ('inf', '+inf', 'infinity', '+infinity'):
        return float('inf')
    if sl in ('-inf', '-infinity'):
        return float('-inf')
    # 允许 0x1.921fb6p+1 这种 hex
    if 'p' in sl and ('x' in sl):
        return float.fromhex(s)
    return float(s)

def main():
    ap = argparse.ArgumentParser(description="浮点数内存表示/IEEE754查看工具")
    ap.add_argument("value", help="浮点数字符串，如 3.14 / -0.0 / nan / inf / 0x1.921fb6p+1")
    ap.add_argument("--prec", choices=['f16', 'f32', 'f64'], default='f64', help="精度：f16/f32/f64 (默认 f64)")
    ap.add_argument("--endian", choices=['little', 'big'], default='little', help="字节序 (默认 little)")
    args = ap.parse_args()

    val = parse_value(args.value)
    info = explain(val, args.prec, args.endian)
    pretty_print(info)

if __name__ == "__main__":
    main()



#python MISC/py代码/float_mem.py 3.1415926 --prec f32
#python MISC/py代码/float_mem.py 3.1415926 --prec f64
#python MISC/py代码/float_mem.py -0.0 --prec f32
#python MISC/py代码/float_mem.py nan --prec f64
#python MISC/py代码/float_mem.py 1.5 --prec f16
#python MISC/py代码/float_mem.py 0x1.921fb6p+1 --prec f64