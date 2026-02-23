#!/usr/bin/env python3

import argparse
import hashlib
import os
from collections import defaultdict


def calculate_file_hash(filepath, block_size=65536):
    """计算文件的SHA-256哈希值"""
    hasher = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for block in iter(lambda: f.read(block_size), b""):
                hasher.update(block)
        return hasher.hexdigest()
    except (IOError, OSError):
        return None


def find_duplicate_files(directory):
    """查找目录中的重复文件"""
    # 按文件大小分组
    size_groups = defaultdict(list)

    # 遍历目录和子目录
    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            try:
                file_size = os.path.getsize(filepath)
                size_groups[file_size].append(filepath)
            except (OSError, IOError):
                # 跳过无法访问的文件
                continue

    # 检查大小相同的文件是否有重复
    duplicates = []
    for size, files in size_groups.items():
        if len(files) > 1:
            # 按哈希值分组
            hash_groups = defaultdict(list)
            for filepath in files:
                file_hash = calculate_file_hash(filepath)
                if file_hash is not None:
                    hash_groups[file_hash].append(filepath)

            # 添加哈希值也相同的文件
            for hash_value, hash_files in hash_groups.items():
                if len(hash_files) > 1:
                    duplicates.append(hash_files)

    return duplicates


def main():
    parser = argparse.ArgumentParser(description="查找目录中的重复文件")
    parser.add_argument("directory", help="要检查的目录路径")
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"错误: '{args.directory}' 不是一个有效的目录")
        return

    print(f"正在检查目录: {args.directory}")
    duplicates = find_duplicate_files(args.directory)

    if duplicates:
        print("\n找到以下重复文件:")
        for i, group in enumerate(duplicates, 1):
            print(f"\n组 {i}:")
            for filepath in group:
                print(f"  {filepath}")
    else:
        print("\n未找到重复文件")


if __name__ == "__main__":
    main()
