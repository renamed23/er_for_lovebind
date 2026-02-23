#!/usr/bin/env python3

"""
一次性 JSON 合并 / 拆分脚本

功能说明：
1. merge 模式：
   - 将目录下多个 JSON 文件合并为一个
   - 每条记录会自动添加 file 字段，表示来源文件名

2. split 模式：
   - 将已合并的 JSON 按 file 字段拆分回多个文件
   - 拆分后会移除 file 字段

约定：
- 所有 JSON 文件最外层必须是数组
- 数据不符合预期直接报错，不做多余容错
"""

import argparse
import json
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List


def collect_files(path: str, suffix: str | None = None):
    if not os.path.isdir(path):
        print(f"错误: {path} 不是文件夹路径")
        exit(1)
    target_files = []
    for root, _, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            # 如果没有指定后缀名，或者文件以指定后缀名结尾，则收集
            if suffix is None or file.lower().endswith(suffix.lower()):
                target_files.append(file_path)
    # 自然排序按相对路径
    target_files.sort(
        key=lambda x: [
            int(p) if p.isdigit() else p.lower()
            for p in re.split(r"(\d+)", os.path.relpath(x, path))
        ]
    )
    return target_files


def merge_jsons(input_dir: str, output_file: str) -> None:
    merged: List[Dict[str, Any]] = []

    for path in collect_files(input_dir, "json"):
        if not os.path.isfile(path):
            continue

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, list):
            raise ValueError(f"文件 {path} 的最外层不是数组")

        for item in data:
            if not isinstance(item, dict):
                raise ValueError(f"文件 {path} 中存在非对象条目")

            item = dict(item)  # 浅拷贝，避免修改原始数据
            item["file"] = Path(path).name
            merged.append(item)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False, indent=2)


def split_json(input_file: str, output_dir: str) -> None:
    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("输入的 JSON 最外层不是数组")

    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for item in data:
        if not isinstance(item, dict):
            raise ValueError("合并文件中存在非对象条目")

        file_name = item.get("file")
        if not file_name:
            raise ValueError("存在缺少 file 字段的条目，无法拆分")

        item = dict(item)  # 拷贝，避免污染原数据
        item.pop("file", None)
        groups[file_name].append(item)

    os.makedirs(output_dir, exist_ok=True)

    for file_name, items in groups.items():
        out_path = os.path.join(output_dir, file_name)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(items, f, ensure_ascii=False, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="JSON 文件合并 / 拆分工具（基于 file 字段）"
    )

    subparsers = parser.add_subparsers(dest="mode", required=True)

    merge_parser = subparsers.add_parser("merge", help="合并目录下多个 JSON 文件为一个")
    merge_parser.add_argument("input_dir", help="包含多个 JSON 文件的目录")
    merge_parser.add_argument("output", help="合并后的输出 JSON 文件路径")

    split_parser = subparsers.add_parser(
        "split", help="将合并后的 JSON 按 file 字段拆分为多个文件"
    )
    split_parser.add_argument("input", help="已合并的 JSON 文件路径")
    split_parser.add_argument("output_dir", help="拆分后输出的目录")

    args = parser.parse_args()

    if args.mode == "merge":
        merge_jsons(args.input_dir, args.output)
    elif args.mode == "split":
        split_json(args.input, args.output_dir)


if __name__ == "__main__":
    main()
