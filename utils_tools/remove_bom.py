#!/usr/bin/env python3

import argparse
import os
import sys


def remove_utf16_bom(directory_path):
    """
    删除指定目录中所有文件的UTF-16 BOM
    如果文件没有BOM，会抛出异常
    """
    # 检查目录是否存在
    if not os.path.exists(directory_path):
        raise FileNotFoundError(f"目录不存在: {directory_path}")

    if not os.path.isdir(directory_path):
        raise NotADirectoryError(f"路径不是目录: {directory_path}")

    # 获取目录中的所有文件（不包括子目录）
    files = [
        f
        for f in os.listdir(directory_path)
        if os.path.isfile(os.path.join(directory_path, f))
    ]

    if not files:
        print("目录中没有文件")
        return

    processed_count = 0
    error_files = []

    for filename in files:
        file_path = os.path.join(directory_path, filename)

        try:
            # 以二进制模式读取文件
            with open(file_path, "rb") as f:
                content = f.read()

            # 检查是否有UTF-16 LE BOM (FF FE)
            if len(content) >= 2 and content[:2] == b"\xff\xfe":
                # 删除BOM并写回文件
                with open(file_path, "wb") as f:
                    f.write(content[2:])
                print(f"✓ 已删除BOM: {filename}")
                processed_count += 1
            else:
                # 检查是否有UTF-16 BE BOM (FE FF)
                if len(content) >= 2 and content[:2] == b"\xfe\xff":
                    with open(file_path, "wb") as f:
                        f.write(content[2:])
                    print(f"✓ 已删除BOM (UTF-16 BE): {filename}")
                    processed_count += 1
                else:
                    error_files.append(filename)
                    print(f"✗ 没有BOM: {filename}")

        except Exception as e:
            error_files.append(f"{filename} (错误: {str(e)})")
            print(f"✗ 处理失败: {filename} - {str(e)}")

    # 输出总结
    print(f"\n=== 处理完成 ===")
    print(f"成功处理: {processed_count} 个文件")

    if error_files:
        print(f"失败文件 ({len(error_files)} 个):")
        for f in error_files:
            print(f"  - {f}")

        # 如果有文件没有BOM，抛出异常
        raise Exception(f"有 {len(error_files)} 个文件没有BOM或处理失败")


if __name__ == "__main__":
    # 设置命令行参数解析
    parser = argparse.ArgumentParser(description="删除目录中所有文件的UTF-16 BOM")
    parser.add_argument("directory", help="要处理的目录路径")

    args = parser.parse_args()

    # 使用命令行参数提供的路径
    DIRECTORY_PATH = args.directory

    try:
        remove_utf16_bom(DIRECTORY_PATH)
        print("\n✅ 所有文件处理成功！")
    except Exception as e:
        print(f"\n❌ 处理失败: {e}")
        sys.exit(1)
