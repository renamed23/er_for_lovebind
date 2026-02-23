#!/usr/bin/env python3

import json
import re


def ascii_to_fullwidth(text, ignore_pattern=None):
    """
    将ASCII字符转换为全角字符，同时忽略指定的控制字符

    参数:
        text: 要转换的文本
        ignore_pattern: 需要忽略的控制字符的正则表达式模式，如果为None或空字符串，则不忽略任何控制字符
    """

    def _convert_text(text):
        """内部使用的转换函数，避免代码重复"""
        converted = ""
        for char in text:
            code = ord(char)
            if code == 32:  # 空格
                converted += "　"  # 全角空格
            elif 33 <= code <= 126:  # 可打印ASCII字符
                converted += chr(code + 65248)  # 转换为全角
            else:
                converted += char  # 其他字符保持不变
        return converted

    if not text:
        return text

    # 如果没有忽略模式，则直接转换整个文本（优化路径）
    if not ignore_pattern:
        return _convert_text(text)

    # 编译正则表达式以提高性能
    pattern = re.compile(ignore_pattern)
    parts = re.split(ignore_pattern, text)
    result_parts = []

    for part in parts:
        # 如果是控制字符，直接保留
        if pattern.fullmatch(part):
            result_parts.append(part)
        else:
            result_parts.append(_convert_text(part))

    return "".join(result_parts)


def process_json_file(input_file, output_file):
    """
    处理JSON文件
    """
    # 定义需要忽略的标记模式
    # ignore_pattern = r'(@W|@P|@L|@N1|@N2)'
    ignore_pattern = None

    try:
        # 读取JSON文件
        with open(input_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        # 处理每个条目
        for item in data:
            if "message" in item:
                item["message"] = ascii_to_fullwidth(
                    item["message"], ignore_pattern)

            if "name" in item:
                item["name"] = ascii_to_fullwidth(item["name"], ignore_pattern)

        # 保存处理后的JSON
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        print(f"处理完成！结果已保存到: {output_file}")

    except FileNotFoundError:
        print(f"错误：找不到文件 {input_file}")
    except json.JSONDecodeError:
        print(f"错误：{input_file} 不是有效的JSON文件")
    except Exception as e:
        print(f"处理过程中出现错误: {e}")


if __name__ == "__main__":
    process_json_file("generated/translated.json", "generated/translated.json")
