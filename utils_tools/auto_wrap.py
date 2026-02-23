#!/usr/bin/env python3

"""
文本换行处理工具
支持自动换行和移除换行两种操作
考虑字符宽度：ASCII字符宽度为1，其他字符宽度为2
"""

import argparse
import json
import sys
from typing import Any, Dict, List

# ------------------------------------------------------
DEFAULT_WRAP_WIDTH = 54
WRAP_SYMBOL = "\r\n"
WRAP_SYMBOL_TO_REMOVE = ["\r\n", "\n"]
SYMBOL_TO_IGNORE_WRAP = ["/"]
SYMBOL_ZERO_WIDTH = ["|"]
# ------------------------------------------------------


def get_char_width(char: str) -> int:
    """获取字符的显示宽度"""
    # ASCII字符（包括半角符号）宽度为1，其他字符宽度为2
    if char in SYMBOL_ZERO_WIDTH:
        return 0
    if ord(char) <= 127:
        return 1
    return 2


def get_string_width(text: str) -> int:
    """获取字符串的总显示宽度"""
    return sum(get_char_width(char) for char in text)


def auto_wrap_string(text: str, max_width: int) -> str:
    """自动换行函数，考虑字符宽度"""
    # 先移除现有的换行符
    text = remove_wrap_string(text)

    # 按字符宽度换行
    lines = []
    current_line = ""
    current_width = 0

    for char in text:
        char_width = get_char_width(char)

        # 如果添加这个字符会超过最大宽度，则换行
        if current_width + char_width > max_width:
            if current_line:  # 确保当前行不为空
                lines.append(current_line)
                current_line = char
                current_width = char_width
            else:  # 当前行为空但单个字符就超过宽度，强制添加
                lines.append(char)
                current_line = ""
                current_width = 0
        else:
            current_line += char
            current_width += char_width

    # 添加最后一行
    if current_line:
        lines.append(current_line)

    return WRAP_SYMBOL.join(lines)


def remove_wrap_string(text: str) -> str:
    """移除换行函数"""
    for symbol in WRAP_SYMBOL_TO_REMOVE:
        text = text.replace(symbol, "")
    return text


def process_json_data(
    data: List[Dict[str, Any]], command: str, max_width: int = DEFAULT_WRAP_WIDTH
) -> List[Dict[str, Any]]:
    """处理JSON数据"""
    processed_data = []

    for item in data:
        # 创建新的字典，保留所有原有字段
        new_item = item.copy()

        # 检查是否有message字段且不包含'/'，并且should_wrap存在且为True
        has_should_wrap = "should_wrap" in item and item["should_wrap"] is True
        has_message = "message" in item and isinstance(item["message"], str)
        should_ignore = has_message and any(
            symbol in item["message"] for symbol in SYMBOL_TO_IGNORE_WRAP
        )

        if has_message and has_should_wrap and not should_ignore:
            if command == "auto_wrap":
                new_item["message"] = auto_wrap_string(item["message"], max_width)
            elif command == "remove_wrap":
                new_item["message"] = remove_wrap_string(item["message"])

        processed_data.append(new_item)

    return processed_data


def main():
    parser = argparse.ArgumentParser(description="文本换行处理工具")
    subparsers = parser.add_subparsers(dest="command", help="子命令", required=True)

    # auto_wrap 子命令
    auto_wrap_parser = subparsers.add_parser("auto_wrap", help="自动换行")
    auto_wrap_parser.add_argument("input_file", help="输入JSON文件")
    auto_wrap_parser.add_argument("output_file", help="输出JSON文件")

    # remove_wrap 子命令
    remove_wrap_parser = subparsers.add_parser("remove_wrap", help="移除换行")
    remove_wrap_parser.add_argument("input_file", help="输入JSON文件")
    remove_wrap_parser.add_argument("output_file", help="输出JSON文件")

    args = parser.parse_args()

    try:
        # 读取输入文件
        with open(args.input_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        # 处理数据
        if args.command == "auto_wrap":
            processed_data = process_json_data(data, "auto_wrap")
        else:  # remove_wrap
            processed_data = process_json_data(data, "remove_wrap")

        # 写入输出文件
        with open(args.output_file, "w", encoding="utf-8") as f:
            json.dump(processed_data, f, ensure_ascii=False, indent=2)

        print(f"处理完成！输出文件: {args.output_file}")

    except FileNotFoundError:
        print(f"错误: 找不到文件 {args.input_file}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"错误: {args.input_file} 不是有效的JSON文件")
        sys.exit(1)
    except Exception as e:
        print(f"处理过程中发生错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
