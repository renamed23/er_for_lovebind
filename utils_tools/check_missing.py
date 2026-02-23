#!/usr/bin/env python3

import os


def main():
    txt_path = "filenames.txt"  # 你的文件名清单
    raw_dir = "raw"  # 要扫描的目录

    # 读取文件名列表
    with open(txt_path, "r", encoding="utf-8") as f:
        expected_files = [line.strip().lower() for line in f if line.strip()]

    # 实际存在的文件
    if not os.path.isdir(raw_dir):
        print(f"错误：找不到目录 {raw_dir}")
        return

    existing_files = set(os.listdir(raw_dir))

    # 找出缺失的文件
    missing_files = [name for name in existing_files if name not in expected_files]

    if missing_files:
        print("以下文件在 raw 目录中缺失：")
        for name in missing_files:
            print(name)
        print(f"\n共缺失 {len(missing_files)} 个文件。")
    else:
        print("✅ 所有文件都存在！")


if __name__ == "__main__":
    main()
