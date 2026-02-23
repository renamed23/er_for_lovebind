#!/usr/bin/env python3

"""
测试辅助工具：生成测试用翻译JSON文件
将提取的文本JSON转换为原文-译文对的JSON（平假名和汉字均替换为"中"）

作者: DeepSeek
版本: 1.0
更新: 2025-07-24
"""

import argparse
import json
import os
import sys


def create_test_translation(input_file, output_file):
    """
    创建测试用翻译JSON文件
    - 将平假名和汉字均替换为"中"
    - 保留所有原始字段
    """

    # 读取提取的文本JSON
    with open(input_file, "r", encoding="utf-8") as f:
        extracted_data = json.load(f)

    # 创建翻译列表
    translation_list = []

    # 遍历所有文本项
    for item in extracted_data:
        # 创建翻译项，首先复制原始项目的所有字段
        translation_item = item.copy()

        for key in ["message"]:
            if translation_item[key].startswith("["):
                translation_item[key] = translation_item[key][:-1]
            else:
                translation_item[key] = translation_item[key][1:]

        # 添加到结果列表
        translation_list.append(translation_item)

    # 保存为JSON文件
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(translation_list, f, ensure_ascii=False, indent=2)

    print(f"成功创建测试翻译文件: {output_file}")
    print(f"共转换 {len(translation_list)} 条文本项")


def main():
    """
    主函数：解析命令行参数并执行转换
    """
    # 创建命令行参数解析器
    parser = argparse.ArgumentParser(
        description='测试辅助工具：生成测试用翻译JSON文件（平假名和汉字替换为"中"）',
        epilog="示例:\n"
        "  python create_test_translation_v2.py extracted.json -o test_translation.json\n",
    )

    # 添加参数
    parser.add_argument("input", help="输入JSON文件路径（提取的文本）")
    parser.add_argument(
        "-o", "--output", required=True, help="输出JSON文件路径（翻译文件）"
    )

    # 解析命令行参数
    args = parser.parse_args()

    try:
        # 检查输入文件是否存在
        if not os.path.exists(args.input):
            raise FileNotFoundError(f"输入文件不存在: {args.input}")

        # 执行转换
        create_test_translation(args.input, args.output)

    except Exception as e:
        # 错误处理
        print(f"错误: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
