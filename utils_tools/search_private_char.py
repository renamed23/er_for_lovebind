#!/usr/bin/env python3

import json


def is_private_char(char):
    """检查字符是否为Unicode私有字符"""
    code_point = ord(char)
    # 私有使用区: U+E000 - U+F8FF
    # 补充私有使用区-A: U+F0000 - U+FFFFF
    # 补充私有使用区-B: U+100000 - U+10FFFF
    return (
        (0xE000 <= code_point <= 0xF8FF)
        or (0xF0000 <= code_point <= 0xFFFFF)
        or (0x100000 <= code_point <= 0x10FFFF)
    )


def scan_private_chars(json_file):
    """扫描JSON文件中的name和message字段里的私有字符"""
    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    private_chars = set()

    for idx, item in enumerate(data):
        # 检查message字段
        if "message" in item and item["message"]:
            for char in item["message"]:
                if is_private_char(char):
                    private_chars.add((char, ord(char)))

        # 检查name字段
        if "name" in item and item["name"]:
            for char in item["name"]:
                if is_private_char(char):
                    private_chars.add((char, ord(char)))

    return private_chars


# 使用示例
if __name__ == "__main__":
    json_file = "raw.json"  # 改成你的文件名

    try:
        chars = scan_private_chars(json_file)

        if chars:
            print(f"发现 {len(chars)} 个不同的私有字符：\n")
            for char, code_point in sorted(chars, key=lambda x: x[1]):
                print(f"字符: {char}")
                print(f"Unicode码点: U+{code_point:04X}")
                print(f"UTF-8编码: {char.encode('utf-8').hex().upper()}")
                print("-" * 30)
        else:
            print("文件中未找到私有字符")

    except FileNotFoundError:
        print(f"错误: 文件 '{json_file}' 不存在")
    except json.JSONDecodeError as e:
        print(f"错误: JSON解析失败 - {e}")
