#!/usr/bin/env python3

"""
文件填充脚本
用于将translated目录中的文件填充到与raw目录中对应文件相同的大小
"""

import argparse
import os
import sys


def parse_hex_string(hex_str):
    """解析十六进制字符串为字节序列"""
    try:
        # 移除空格并转换为字节
        hex_str = hex_str.replace(" ", "")
        if len(hex_str) % 2 != 0:
            raise ValueError("十六进制字符串长度必须是偶数")
        return bytes.fromhex(hex_str)
    except ValueError as e:
        print(f"错误：无法解析十六进制字符串 '{hex_str}': {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="文件填充脚本")
    parser.add_argument("raw", help="原始文件目录路径")
    parser.add_argument("translated", help="翻译后文件目录路径")
    parser.add_argument("pattern", help='填充模式字节字符串（如 "00 01"）')
    parser.add_argument("fallback", nargs="?", help="可选的备用填充字节（单字节）")

    args = parser.parse_args()

    # 检查目录是否存在
    if not os.path.isdir(args.raw):
        print(f"错误：原始目录 '{args.raw}' 不存在")
        sys.exit(1)

    if not os.path.isdir(args.translated):
        print(f"错误：翻译目录 '{args.translated}' 不存在")
        sys.exit(1)

    # 解析填充模式字节
    pattern_bytes = parse_hex_string(args.pattern)

    # 解析备用填充字节（如果提供）
    fallback_byte = None
    if args.fallback:
        fallback_bytes = parse_hex_string(args.fallback)
        if len(fallback_bytes) != 1:
            print(f"错误：备用填充字节必须是单字节，但得到 {len(fallback_bytes)} 字节")
            sys.exit(1)
        fallback_byte = fallback_bytes[0]

    # 遍历translated目录中的所有文件
    for root, dirs, files in os.walk(args.translated):
        for file in files:
            # 构建翻译文件的完整路径
            translated_file_path = os.path.join(root, file)

            # 计算相对于translated目录的相对路径
            relative_path = os.path.relpath(translated_file_path, args.translated)

            # 构建对应的原始文件路径
            raw_file_path = os.path.join(args.raw, relative_path)

            # 检查原始文件是否存在
            if not os.path.exists(raw_file_path):
                print(f"错误：找不到对应的原始文件 '{raw_file_path}'")
                sys.exit(1)

            # 获取文件大小
            raw_size = os.path.getsize(raw_file_path)
            translated_size = os.path.getsize(translated_file_path)

            # 检查翻译文件是否更大
            if translated_size > raw_size:
                print(
                    f"错误：翻译文件 '{translated_file_path}' ({translated_size} 字节) 大于原始文件 '{raw_file_path}' ({raw_size} 字节)"
                )
                sys.exit(1)

            # 如果大小相同，无需处理
            if translated_size == raw_size:
                continue

            # 计算需要填充的字节数
            padding_needed = raw_size - translated_size

            print(f"处理文件: {relative_path}")
            print(f"  原始大小: {raw_size} 字节")
            print(f"  当前大小: {translated_size} 字节")
            print(f"  需要填充: {padding_needed} 字节")

            # 构建填充数据
            padding_data = b""

            # 尝试使用模式字节填充
            if len(pattern_bytes) > 0:
                # 计算模式字节可以完整填充的次数
                full_patterns = padding_needed // len(pattern_bytes)
                remainder = padding_needed % len(pattern_bytes)

                # 添加完整的模式字节
                padding_data += pattern_bytes * full_patterns

                # 如果有剩余字节，使用模式字节的前缀
                if remainder > 0:
                    padding_data += pattern_bytes[:remainder]

                # 检查是否完美填充
                if len(padding_data) == padding_needed:
                    print(f"  使用模式字节完美填充")
                else:
                    # 如果不完美且没有备用字节，报错
                    if fallback_byte is None:
                        print(
                            f"错误：无法用模式字节完美填充文件 '{translated_file_path}'，且未提供备用填充字节"
                        )
                        sys.exit(1)
                    # 使用备用字节继续填充
                    remaining_padding = padding_needed - len(padding_data)
                    padding_data += bytes([fallback_byte]) * remaining_padding
                    print(f"  使用模式字节和备用字节填充")
            else:
                # 模式字节为空，使用备用字节填充
                if fallback_byte is None:
                    print(f"错误：模式字节为空且未提供备用填充字节")
                    sys.exit(1)
                padding_data = bytes([fallback_byte]) * padding_needed
                print(f"  使用备用字节填充")

            # 执行填充
            try:
                with open(translated_file_path, "ab") as f:  # 以追加二进制模式打开
                    f.write(padding_data)

                # 验证填充后的文件大小
                new_size = os.path.getsize(translated_file_path)
                if new_size != raw_size:
                    print(
                        f"错误：填充后文件大小不匹配，期望 {raw_size} 字节，实际 {new_size} 字节"
                    )
                    sys.exit(1)

                print(f"  填充完成，新大小: {new_size} 字节")

            except Exception as e:
                print(f"错误：处理文件 '{translated_file_path}' 时发生异常: {e}")
                sys.exit(1)

    print("所有文件处理完成！")


if __name__ == "__main__":
    main()
