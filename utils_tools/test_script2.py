#!/usr/bin/env python3

"""
测试辅助工具：生成测试用翻译JSON文件
将提取的文本JSON转换为原文-译文对的JSON（用原文填充译文）

作者: DeepSeek
版本: 1.2
更新: 2025-07-24
"""

import argparse
import json
import os
import sys


def create_test_translation(input_file, output_file):
    """
    创建测试用翻译JSON文件
    - 将日文假名映射为指定汉字
    - 删除指定假名
    - 保留所有原始字段
    """

    # 假名到汉字的映射表（你可以自由增删）
    kana_map = {
        "あ": "你",
        "い": "一",
        "う": "宇",
        "え": "衣",
        "お": "於",
        "か": "加",
        "き": "木",
        "く": "久",
        "け": "計",
        "こ": "古",
        "さ": "左",
        "し": "志",
        "す": "寿",
        "せ": "世",
        "そ": "曽",
        "な": "奈",
        "に": "仁",
        "ぬ": "奴",
        "ね": "祢",
        "の": "乃",
        "ま": "麻",
        "み": "美",
        "む": "啊",
        "め": "女",
        "も": "毛",
        "や": "也",
        "ゆ": "由",
        "よ": "与",
        "ら": "良",
        "り": "利",
        "る": "流",
        "れ": "礼",
        "ろ": "呂",
        "わ": "和",
        "を": "乎",
        "ん": "ン",  # 特殊：把「ん」映射为片假名「ン」
        "ア": "亜",
        "イ": "伊",
        "ウ": "宇",
        "エ": "江",
        "オ": "央",
        "カ": "加",
        "キ": "機",
        "ク": "久",
        "ケ": "計",
        "コ": "古",
        "サ": "佐",
        "シ": "司",
        "ス": "須",
        "セ": "世",
        "ソ": "曽",
        "ン": "心",
    }

    # 要删除的假名集合
    kana_remove = {"ゃ", "ゅ", "ょ", "っ", "ァ", "ィ", "ゥ", "ェ", "ォ"}

    # 读取提取的文本JSON
    with open(input_file, "r", encoding="utf-8") as f:
        extracted_data = json.load(f)

    # 创建翻译列表
    translation_list = []

    # 遍历所有文本项
    for item in extracted_data:
        # 创建翻译项，首先复制原始项目的所有字段
        translation_item = item.copy()

        # 处理message字段（如果存在）
        if "message" in translation_item:
            # 映射 & 删除假名
            new_message_chars = []
            for ch in translation_item["message"]:
                if ch in kana_remove:
                    continue  # 跳过（删除）指定假名
                elif ch in kana_map:
                    new_message_chars.append(kana_map[ch])  # 替换成汉字
                else:
                    new_message_chars.append(ch)  # 保持原样

            translation_item["message"] = "".join(new_message_chars)

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
        description="测试辅助工具：生成测试用翻译JSON文件",
        epilog="示例:\n"
        "  python create_test_translation.py extracted.json -o test_translation.json\n",
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
