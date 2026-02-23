#!/usr/bin/env python3

import argparse
import json
from typing import Dict, List


def filter_messages(
    input_data: List[Dict[str, str]], max_length: int
) -> List[Dict[str, str]]:
    """
    过滤消息列表，保留长度不超过指定字符数的消息，并去重

    Args:
        input_data: 输入的消息字典列表
        max_length: 最大字符数限制

    Returns:
        过滤并去重后的消息字典列表
    """
    seen_messages = set()
    result = []

    for item in input_data:
        has_name = "name" in item
        message = item["message"]
        # 检查消息长度和是否重复
        if len(message) <= max_length and message not in seen_messages and not has_name:
            result.append({"message": message})
            seen_messages.add(message)

    return result


def main():
    # 设置命令行参数解析
    parser = argparse.ArgumentParser(description="过滤JSON消息并按字符长度去重")
    parser.add_argument("input", help="输入JSON文件路径")
    parser.add_argument("length", type=int, help="最大字符数量")
    parser.add_argument(
        "--output", default="outname.json", help="输出JSON文件路径，默认为outname.json"
    )

    args = parser.parse_args()

    try:
        # 读取输入JSON文件
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)

        # 过滤和去重消息
        filtered_data = filter_messages(data, args.length)

        # 写入输出文件
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(filtered_data, f, ensure_ascii=False, indent=2)

        print(f"处理完成！共保留 {len(filtered_data)} 条消息，已保存到 {args.output}")

    except FileNotFoundError:
        print(f"错误：找不到输入文件 {args.input}")
    except json.JSONDecodeError:
        print(f"错误：文件 {args.input} 不是有效的JSON格式")
    except Exception as e:
        print(f"处理过程中发生错误：{str(e)}")


if __name__ == "__main__":
    main()
