#!/usr/bin/env python3

import argparse
import glob
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any, Literal, Tuple

# ----------------------------------- 实用工具 ----------------------------------------


def system(command, check=True, capture_output=False, timeout=None, **kwargs):
    """
    增强版的 os.system()，使用 subprocess.run 实现

    参数:
        command: 要执行的命令字符串
        check: 如果为True，命令失败时会抛出异常（默认True）
        capture_output: 如果为True，捕获命令输出（默认False）
        timeout: 命令超时时间（秒）
        **kwargs: 其他传递给 subprocess.run 的参数

    返回:
        如果 capture_output=True，返回 CompletedProcess 对象
        否则返回命令的退出码
    """
    try:
        # 使用 shell=True 来保持与 os.system() 相同的行为
        result = subprocess.run(
            command,
            shell=True,
            check=check,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            **kwargs,
        )

        if capture_output:
            return result
        else:
            return result.returncode

    except subprocess.CalledProcessError as e:
        if capture_output:
            # 重新抛出异常，但包含输出信息
            raise e
        print(f"命令执行失败，退出码: {e.returncode}", file=sys.stderr)
        if e.stderr:
            print(f"错误信息: {e.stderr}", file=sys.stderr)
        raise
    except subprocess.TimeoutExpired:
        print(f"命令执行超时 (>{timeout}秒)", file=sys.stderr)
        raise


def rename_file(original_path, new_name, overwrite=False):
    """
    将原始文件重命名为新的文件名

    参数:
    original_path (str): 原始文件的完整路径
    new_name (str): 新的文件名（包含扩展名）
    overwrite (bool): 如果目标文件已存在，是否覆盖它 (默认为False)
    """
    # 获取原始文件所在的目录
    directory = os.path.dirname(original_path)

    # 构建新的完整文件路径
    new_path = os.path.join(directory, new_name)

    # 检查目标文件是否已存在
    if os.path.exists(new_path):
        if overwrite:
            # 如果允许覆盖，则删除已存在的文件
            os.remove(new_path)
            print(f"已删除已存在的文件: {new_path}")
        else:
            # 如果不允许覆盖，则抛出异常
            raise FileExistsError(f"目标文件已存在: {new_path}")

    # 执行重命名操作
    os.rename(original_path, new_path)

    print(f"文件重命名成功: {original_path} -> {new_path}")


def change_file_extensions(directory, old_extension, new_extension, overwrite=False):
    """
    修改目录中指定后缀名的文件

    参数:
    directory (str): 目录路径
    old_extension (str): 需要修改的后缀名（如 '.txt'）
    new_extension (str): 修改后的后缀名（如 '.md'）
    overwrite (bool): 如果修改后有同名文件是否覆盖 (默认为False)
    """
    # 确保目录存在
    if not os.path.exists(directory):
        raise FileNotFoundError(f"目录不存在: {directory}")

    # 确保目录是一个目录而不是文件
    if not os.path.isdir(directory):
        raise NotADirectoryError(f"路径不是目录: {directory}")

    # 构建搜索模式
    search_pattern = os.path.join(directory, f"*{old_extension}")

    # 获取所有匹配的文件
    matching_files = glob.glob(search_pattern)

    if not matching_files:
        print(f"在目录 {directory} 中没有找到以 {old_extension} 结尾的文件")
        return

    print(f"找到 {len(matching_files)} 个以 {old_extension} 结尾的文件")

    # 统计成功和失败的数量
    success_count = 0
    fail_count = 0

    for file_path in matching_files:
        try:
            # 获取文件名（不含路径）
            filename = os.path.basename(file_path)

            # 构建新的文件名（替换扩展名）
            new_filename = filename.replace(old_extension, new_extension)

            # 如果新旧文件名相同，跳过
            if filename == new_filename:
                print(f"跳过文件 {filename}（新旧文件名相同）")
                continue

            # 调用重命名函数
            rename_file(file_path, new_filename, overwrite)
            success_count += 1

        except FileExistsError as e:
            print(f"重命名失败: {e}")
            fail_count += 1
        except Exception as e:
            print(f"重命名失败: {e}")
            fail_count += 1

    print(f"操作完成: 成功 {success_count} 个, 失败 {fail_count} 个")


def create_cli(extract_func, replace_func, description="CLI 工具", prog_name=None):
    """创建一个具有 extract 和 replace 子命令的 CLI"""

    def main():
        parser = argparse.ArgumentParser(
            description=description, prog=prog_name)
        subparsers = parser.add_subparsers(dest="command", help="可用命令")

        subparsers.add_parser(
            "e", help="执行提取操作").set_defaults(func=extract_func)
        subparsers.add_parser(
            "r", help="执行替换操作").set_defaults(func=replace_func)

        args = parser.parse_args()

        if not hasattr(args, "func"):
            parser.print_help()
            sys.exit(1)

        args.func()

    return main


def copy_path(source, destination, overwrite=False):
    """
    复制文件或目录到目标位置

    参数:
        source (str): 源文件或目录路径
        destination (str): 目标路径
        overwrite (bool): 如果为True，则覆盖已存在的文件/目录；如果为False，则不覆盖
    """
    source_path = Path(source)
    dest_path = Path(destination)

    # 检查源路径是否存在
    if not source_path.exists():
        raise FileNotFoundError(f"源路径 '{source}' 不存在")

    # 如果目标是目录，且源是文件，则在目标目录中保持原文件名
    if dest_path.is_dir() and source_path.is_file():
        dest_path = dest_path / source_path.name

    # 检查目标路径是否存在
    if dest_path.exists():
        if not overwrite:
            raise FileExistsError(
                f"目标路径 '{dest_path}' 已存在，跳过复制（overwrite=False）"
            )
        else:
            # 如果目标存在且需要覆盖，先删除目标
            if dest_path.is_file():
                dest_path.unlink()
            else:
                shutil.rmtree(dest_path)
            print(f"提示: 已删除已存在的目标路径 '{dest_path}'")

    # 确保目标目录的父目录存在
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    # 复制文件或目录
    if source_path.is_file():
        shutil.copy2(source_path, dest_path)
        print(f"文件复制成功: '{source_path}' -> '{dest_path}'")
    elif source_path.is_dir():
        shutil.copytree(source_path, dest_path)
        print(f"目录复制成功: '{source_path}' -> '{dest_path}'")
    else:
        raise ValueError(f"源路径 '{source_path}' 不是文件或目录")


def merge_directories(source, destination, overwrite=False):
    """
    将源目录合并到目标目录中

    参数:
        source (str): 源目录路径
        destination (str): 目标目录路径
        overwrite (bool): 如果为True，则覆盖已存在的文件；如果为False，则跳过已存在的文件

    行为:
        - 将源目录中的所有文件和子目录复制到目标目录
        - 如果目标目录中已存在同名文件，根据overwrite参数决定是否覆盖
        - 如果目标目录中已存在同名目录，则递归合并
        - 不会删除目标目录中已有的、在源目录中不存在的文件
    """
    source_path = Path(source)
    dest_path = Path(destination)

    # 检查源目录是否存在
    if not source_path.exists():
        raise FileNotFoundError(f"源目录 '{source}' 不存在")

    if not source_path.is_dir():
        raise NotADirectoryError(f"源路径 '{source}' 不是目录")

    # 确保目标目录的父目录存在
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    # 如果目标目录不存在，直接复制整个目录
    if not dest_path.exists():
        shutil.copytree(source_path, dest_path)
        print(f"目录复制成功: '{source_path}' -> '{dest_path}'")
        return

    # 确保目标路径是目录
    if not dest_path.is_dir():
        raise NotADirectoryError(f"目标路径 '{destination}' 不是目录")

    # 遍历源目录中的所有项目
    for item in source_path.iterdir():
        dest_item = dest_path / item.name

        if item.is_file():
            # 处理文件
            if dest_item.exists():
                if overwrite:
                    # 覆盖已存在的文件
                    shutil.copy2(item, dest_item)
                    print(f"覆盖文件: '{item}' -> '{dest_item}'")
                else:
                    print(f"跳过已存在的文件: '{dest_item}'")
            else:
                # 复制新文件
                shutil.copy2(item, dest_item)
                print(f"复制文件: '{item}' -> '{dest_item}'")

        elif item.is_dir():
            # 处理目录 - 递归合并
            if dest_item.exists() and dest_item.is_dir():
                # 目录已存在，递归合并
                merge_directories(item, dest_item, overwrite)
            else:
                # 目录不存在，直接复制整个目录
                if dest_item.exists():
                    # 目标路径存在但不是目录，需要先删除
                    if overwrite:
                        if dest_item.is_file():
                            dest_item.unlink()
                        else:
                            shutil.rmtree(dest_item)
                        shutil.copytree(item, dest_item)
                        print(f"覆盖目录: '{item}' -> '{dest_item}'")
                    else:
                        print(f"跳过已存在的非目录项: '{dest_item}'")
                else:
                    shutil.copytree(item, dest_item)
                    print(f"复制目录: '{item}' -> '{dest_item}'")

    print(f"目录合并完成: '{source_path}' -> '{dest_path}'")


# --------------------------- 特定的编译工具 ----------------------------------


class TextHookBuilder:
    def __init__(self, project_path):
        """
        初始化 TextHookBuilder

        参数:
            project_path (str): 项目目录路径
        """
        self.project_path = Path(project_path)
        self.current_dir = Path.cwd()
        self.assets_dir = self.project_path / "crates" / "text-hook" / "assets"
        self.generated_dir = self.current_dir / "generated"
        self.dist_dir = self.current_dir / "generated" / "dist"

    def copy_assets_for_build(self):
        """
        复制构建所需的资源文件
        """
        # 确保 assets 目录存在
        self.assets_dir.mkdir(parents=True, exist_ok=True)

        # 检查并删除 assets 中的 dist 目录（如果存在）
        assets_dist = self.assets_dir / "dist"
        if assets_dist.exists():
            shutil.rmtree(assets_dist)
            print(f"已删除 assets 中的 dist 目录: {assets_dist}")

        # 处理 font 和 hijacked 目录
        asset_dirs = ["font", "hijacked", "x64dbg_1337_patch"]
        for dir_name in asset_dirs:
            current_dir = self.current_dir / "assets" / dir_name
            target_dir = self.assets_dir / dir_name

            if current_dir.exists() and any(current_dir.iterdir()):
                print(f"检测到非空的 {dir_name} 目录: {current_dir}")

                # 删除目标目录（如果存在）
                if target_dir.exists():
                    shutil.rmtree(target_dir)
                    print(f"已删除目标 {dir_name} 目录: {target_dir}")

                # 复制当前工作目录的目录到目标位置
                copy_path(str(current_dir), str(target_dir), overwrite=True)
            else:
                print(f"{dir_name} 目录不存在或为空: {current_dir}")

        # 处理 raw 和 translated 目录
        patch_dirs = ["raw", "translated", "raw_text",
                      "translated_text", "resource_pack", "misc"]
        for dir_name in patch_dirs:
            current_dir = self.generated_dir / dir_name
            target_dir = self.assets_dir / dir_name

            # 删除目标目录（如果存在）
            if target_dir.exists():
                shutil.rmtree(target_dir)
                print(f"已删除: {target_dir}")

            # 复制当前工作目录的目录
            if current_dir.exists():
                copy_path(str(current_dir), str(target_dir), overwrite=True)
            else:
                print(f"源 {dir_name} 目录不存在: {current_dir}，忽略")

        # 处理配置文件
        config_files = [
            "mapping.json",
            "translated.json",
            "raw.json",
            "config.json",
            "hook_lists.json",
            "sjis_ext.bin",
        ]
        for filename in config_files:
            src_file = self.generated_dir / filename
            if src_file.exists():
                print(f"复制 {filename}")
                copy_path(str(src_file), str(self.assets_dir), overwrite=True)

    def build_dll(self, features, arch="x86", panic="unwind", clean=False):
        """
        构建 DLL 文件

        参数:
            features (List[str]): cargo build 的 features 参数
            arch (str): "x86" 或 "x64"（默认 "x86"）
            panic (str): "unwind", "abort", "immediate-abort"（默认 "unwind"）
            clean (bool): 是否在构建前执行 `cargo clean`（默认 False）
        """
        # 验证 panic 参数
        if panic not in ("unwind", "abort", "immediate-abort"):
            raise ValueError(
                "panic 参数必须是 'unwind', 'abort', 'immediate-abort' 其中之一"
            )

        # 1. 架构映射逻辑
        if arch == "x86":
            alias = "build-text-hook"
            source_dll_rel = Path(
                "target/i686-pc-windows-msvc/release/text_hook.dll")
        elif arch == "x64":
            alias = "build-text-hook64"
            source_dll_rel = Path(
                "target/x86_64-pc-windows-msvc/release/text_hook.dll")
        else:
            raise ValueError("arch 参数必须是 'x86' 或 'x64'")

        # 确保 dist 目录存在
        self.dist_dir.mkdir(parents=True, exist_ok=True)

        # 2. 组装 RUSTFLAGS 和命令
        features_joined = ",".join(features)
        if panic == "immediate-abort":
            # immediate-abort 需要 nightly 工具链和 unstable 选项
            build_command = f"cargo +nightly {alias} --features {features_joined} -Z build-std"
            rustflags = "-C panic=immediate-abort -Z unstable-options"
            print(f"使用 Nightly 工具链编译 (immediate-abort 模式)")
        else:
            build_command = f"cargo {alias} --features {features_joined}"
            rustflags = f"-C panic={panic}"

        print(f"在项目根目录 {self.project_path} 中执行构建命令: {build_command}")
        print(f"目标架构: {arch}, 使用 panic 策略: {panic}")

        # 设置 RUSTFLAGS
        os.environ["RUSTFLAGS"] = rustflags

        # 3. 执行构建流程
        if clean:
            print("执行 cargo clean 以确保所有依赖按新策略重新编译...")
            system("cargo clean", cwd=str(self.project_path))

        # 执行构建
        system(build_command, cwd=str(self.project_path))

        # 4. 复制生成的 DLL 文件
        source_dll = self.project_path / source_dll_rel
        if not source_dll.exists():
            raise FileNotFoundError(f"找不到生成的 DLL 文件: {source_dll}")

        dest_dll = self.dist_dir / "text_hook.dll"
        copy_path(str(source_dll), str(dest_dll), overwrite=True)

        # 5. 检查 hijacked 目录并重命名
        hijacked_dir = self.current_dir / "assets" / "hijacked"
        if hijacked_dir.exists() and any(hijacked_dir.iterdir()):
            print(f"检测到非空的 hijacked 目录: {hijacked_dir}")
            hijacked_files = list(hijacked_dir.iterdir())

            if len(hijacked_files) == 1:
                new_dll_name = hijacked_files[0].name
                print(f"将 DLL 重命名为: {new_dll_name}")
                rename_file(str(dest_dll), new_dll_name, overwrite=True)
            else:
                print(f"警告: hijacked 目录包含 {len(hijacked_files)} 个文件，但预期只有1个文件")
                print("跳过 DLL 重命名")
        else:
            print(f"hijacked 目录不存在或为空: {hijacked_dir}")

        # 6. 检查 assets 中是否有 dist 目录，有则合并到 dist_dir
        assets_dist = self.assets_dir / "dist"
        if assets_dist.exists():
            print(f"检测到 assets 中的 dist 目录，合并到: {self.dist_dir}")
            merge_directories(str(assets_dist), str(
                self.dist_dir), overwrite=True)
            print("合并完成")

        print(f"DLL 构建并复制成功: {dest_dll}")

    def build(self, features, arch="x86", panic="unwind", clean=False):
        """
        完整的构建流程

        参数:
            features (List[str]): cargo build 的 features 参数
            arch (str): "x86" 或 "x64"
            panic (str): "unwind", "abort", "immediate-abort"（默认 "unwind"）
            clean (bool): 是否在构建前执行 `cargo clean`（默认 False）
        """
        print(f"开始构建流程 ({arch})...")
        print(f"panic 策略: {panic}")

        # 复制资源文件
        self.copy_assets_for_build()
        print("资源文件复制完成")

        # 构建 DLL
        self.build_dll(features, arch=arch, panic=panic, clean=clean)
        print("构建流程完成")


def json_check():
    """
    执行 JSON 检查，调用 `python utils_tools/json_check.py raw.json generated/translated.json`
    """
    print("开始 JSON 检查...")
    command = "python utils_tools/json_check.py raw.json generated/translated.json"
    system(command)
    print("JSON 检查完成")


def json_process(mode, file_path):
    """
    处理JSON文件

    参数:
        mode: 处理模式，'e' 或 'r' 或者拓展模式
        file_path: JSON文件路径
    """
    print(f"开始处理JSON文件...")
    print(f"模式: {mode}, 文件: {file_path}")

    # 构建命令
    command = f'python utils_tools/json_processor.py {mode} "{file_path}"'

    # 执行命令
    system(command)
    print("JSON文件处理完成")


def ascii_to_fullwidth():
    """
    执行 ASCII 到全角字符转换，调用 `python utils_tools/ascii_to_width.py`
    """
    print("开始 ASCII 到全角字符转换...")
    command = "python utils_tools/ascii_to_width.py"
    system(command)
    print("ASCII 到全角字符转换完成")


def replace(encoding="CP932", exclude_raw=False, exclude_message=None, filter_rare=False):
    """
    执行替换流程：
    1. 根据编码生成替换池
    2. 应用替换映射

    参数:
        exclude_message: 如果提供，将生成 generated/excluded.json 并添加到命令中
    """
    print("开始替换流程...")

    # 步骤1: 生成替换池
    print("生成替换池...")

    # 构建排除路径列表
    exclude_paths = ["generated/translated.json"]

    if exclude_raw:
        exclude_paths.append("generated/raw.json")

    if exclude_message is not None:
        print("生成排除消息文件...")
        os.makedirs("generated", exist_ok=True)

        # 写入JSON文件
        with open("generated/excluded.json", "w", encoding="utf-8") as f:
            json.dump([{"message": exclude_message}],
                      f, ensure_ascii=False, indent=2)

        exclude_paths.append("generated/excluded.json")
        print("排除消息文件生成完成")

    # 构建排除路径参数
    exclude_args = " ".join([f'--path "{path}"' for path in exclude_paths])

    if filter_rare:
        filter_rare_arg = "--filter-rare"
    else:
        filter_rare_arg = ""

    command1 = f'python ./utils_tools/replacement_tool.py generate-pool --output generated/replacement_pool.json {filter_rare_arg} --encoding "{encoding}" {exclude_args}'
    system(command1)
    print("替换池生成完成")

    # 步骤2: 应用替换映射
    print("应用替换映射...")
    command2 = "python ./utils_tools/replacement_tool.py map --path generated/translated.json --output generated --replacement-pool generated/replacement_pool.json"
    system(command2)
    print("替换映射应用完成")

    print("替换流程完成")


def truncate():
    """
    执行截断流程
    """
    print("开始截断...")
    command = "python utils_tools/truncate.py"
    system(command)
    print("截断完成")


def remove_wrap():
    """
    删除json的换行字符
    """
    print("开始删除json的换行字符...")
    command = "python utils_tools/auto_wrap.py remove_wrap raw.json raw.json"
    system(command)
    print("删除json的换行字符完成")


def auto_wrap():
    """
    自动进行换行json
    """
    print("开始自动进行换行...")
    command = "python utils_tools/auto_wrap.py auto_wrap generated/translated.json generated/translated.json"
    system(command)
    print("自动进行换行完成")


def generate_json(config: dict, filename: str = "config.json"):
    """
    根据字典生成json
    """

    print(f"生成 {filename}...")

    with open(f"generated/{filename}", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


def auto_padding(
    pattern_bytes,
    fallback_byte=None,
    raw_dir="generated/raw",
    translated_dir="generated/translated",
):
    """
    自动进行文件填充

    参数:
        pattern_bytes: 填充模式字节字符串（如 "00 01"）
        fallback_byte: 可选的备用填充字节字符串（单字节，如 "FF"）
        raw_dir: raw目录路径，默认为 "generated/raw"
        translated_dir: translated目录路径，默认为 "generated/translated"
    """
    print("开始自动进行文件填充...")

    # 构建命令
    command = (
        f'python utils_tools/padding.py {raw_dir} {translated_dir} "{pattern_bytes}"'
    )

    # 如果提供了备用字节，添加到命令中
    if fallback_byte is not None:
        command += f' "{fallback_byte}"'

    # 执行命令
    system(command)
    print("自动进行文件填充完成")


def extract_and_concat(er: list[tuple[str, str]], e_fn_before=None, e_fn_after=None):
    """
    运行每一个e命令，若e_fn_before不为None，则先调用它，若e_fn_after不为None，则在e命令运行后调用它
    最后将其整合为一个raw.json
    """
    results = []
    split_idx_list = []
    idx = 0
    for i, (e, _) in enumerate(er):
        if e_fn_before != None:
            e_fn_before(i)
        system(e)
        if e_fn_after != None:
            e_fn_after(i)
        with open("raw.json", "r", encoding="utf-8") as f:
            raw = json.load(f)
        idx += len(raw)
        split_idx_list.append(idx)
        results.extend(raw)

    with open("raw.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    with open("splits.json", "w", encoding="utf-8") as f:
        json.dump(split_idx_list, f, indent=2, ensure_ascii=False)


def split_and_replace(er: list[tuple[str, str]], r_fn_before=None, r_fn_after=None):
    """
    将generated/translated.json依次拆散为独立的translated.json，
    若r_fn_before不为None则先调用它，然后调用对应的r命令，若r_fn_after不为None则调用它。
    最后还原generated/translated.json。
    """
    with open("generated/translated.json", "r", encoding="utf-8") as f:
        results = json.load(f)
    with open("splits.json", "r", encoding="utf-8") as f:
        split_idx_list = json.load(f)

    original_results = results.copy()

    idx = 0
    for i, (_, r) in enumerate(er):
        with open("generated/translated.json", "w", encoding="utf-8") as f:
            json.dump(results[idx: split_idx_list[i]],
                      f, indent=2, ensure_ascii=False)
            idx = split_idx_list[i]
        if r_fn_before != None:
            r_fn_before(i)
        system(r)
        if r_fn_after != None:
            r_fn_after(i)

    # 还原原来的 generated/translated.json
    with open("generated/translated.json", "w", encoding="utf-8") as f:
        json.dump(original_results, f, indent=2, ensure_ascii=False)


def generate_empty_mapping(code_page=932):
    """
    创建一个空的映射，一般配合`no_text_mapping`使用
    """
    with open("generated/mapping.json", "w", encoding="utf-8") as f:
        json.dump(
            {"code_page": code_page, "mapping": {}}, f, indent=2, ensure_ascii=False
        )


# ----------------------------------- ER和PACKER工具 ----------------------------------------


def bytes_to_hex_string(data: bytes) -> str:
    return " ".join(f"{byte:02X}" for byte in data)


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


def read_str_until_null(data: bytes, offset: int, encoding="CP932") -> Tuple[str, int]:
    """读取直到null结尾的字符串，返回(字符串, 新的offset)"""
    end = data.find(0x00, offset)
    if end == -1:
        raise ValueError(f"在偏移 {hex(offset)} 处找不到字符串结尾")
    s = data[offset:end].decode(encoding)
    return s, end + 1  # 包含null字节


def read_u8(data: bytes, offset: int) -> Tuple[int, int]:
    """读取1字节无符号整数，返回(值, 新的offset)"""
    if offset + 1 > len(data):
        raise ValueError("数据不足，无法读取u8")
    return data[offset], offset + 1


def read_u16(data: bytes, offset: int) -> Tuple[int, int]:
    """读取2字节无符号整数(小端序)，返回(值, 新的offset)"""
    if offset + 2 > len(data):
        raise ValueError("数据不足，无法读取u16")
    return struct.unpack("<H", data[offset: offset + 2])[0], offset + 2


def read_u32(data: bytes, offset: int) -> Tuple[int, int]:
    """读取4字节无符号整数(小端序)，返回(值, 新的offset)"""
    if offset + 4 > len(data):
        raise ValueError("数据不足，无法读取u32")
    return struct.unpack("<I", data[offset: offset + 4])[0], offset + 4


def read_i8(data: bytes, offset: int) -> Tuple[int, int]:
    """读取1字节有符号整数，返回(值, 新的offset)"""
    if offset + 1 > len(data):
        raise ValueError("数据不足，无法读取i8")
    return struct.unpack("<b", data[offset: offset + 1])[0], offset + 1


def read_i16(data: bytes, offset: int) -> Tuple[int, int]:
    """读取2字节有符号整数(小端序)，返回(值, 新的offset)"""
    if offset + 2 > len(data):
        raise ValueError("数据不足，无法读取i16")
    return struct.unpack("<h", data[offset: offset + 2])[0], offset + 2


def read_i32(data: bytes, offset: int) -> Tuple[int, int]:
    """读取4字节有符号整数(小端序)，返回(值, 新的offset)"""
    if offset + 4 > len(data):
        raise ValueError("数据不足，无法读取i32")
    return struct.unpack("<i", data[offset: offset + 4])[0], offset + 4


def read_bytes(data: bytes, offset: int, length: int) -> Tuple[bytes, int]:
    """读取固定长度的字节片段，返回(值, 新的offset)"""
    slice_data = data[offset: offset + length]
    return slice_data, offset + length


def read_u8_s(data: bytes, offset: int) -> Tuple[str, int]:
    """读取1字节无符号整数，返回(格式化字符串, 新的offset)"""
    val, offset = read_u8(data, offset)
    return se(val, "u8"), offset


def read_u16_s(data: bytes, offset: int) -> Tuple[str, int]:
    """读取2字节无符号整数(小端序)，返回(格式化字符串, 新的offset)"""
    val, offset = read_u16(data, offset)
    return se(val, "u16"), offset


def read_u32_s(data: bytes, offset: int) -> Tuple[str, int]:
    """读取4字节无符号整数(小端序)，返回(格式化字符串, 新的offset)"""
    val, offset = read_u32(data, offset)
    return se(val, "u32"), offset


def read_i8_s(data: bytes, offset: int) -> Tuple[str, int]:
    """读取1字节有符号整数，返回(格式化字符串, 新的offset)"""
    val, offset = read_i8(data, offset)
    return se(val, "i8"), offset


def read_i16_s(data: bytes, offset: int) -> Tuple[str, int]:
    """读取2字节有符号整数(小端序)，返回(格式化字符串, 新的offset)"""
    val, offset = read_i16(data, offset)
    return se(val, "i16"), offset


def read_i32_s(data: bytes, offset: int) -> Tuple[str, int]:
    """读取4字节有符号整数(小端序)，返回(格式化字符串, 新的offset)"""
    val, offset = read_i32(data, offset)
    return se(val, "i32"), offset


def read_str_s(data: bytes, offset: int) -> Tuple[str, int]:
    """读取null结尾的字符串，返回(格式化字符串, 新的offset)"""
    val, offset = read_str_until_null(data, offset)
    return se(val, "str"), offset


def read_bytes_s(data: bytes, offset: int, length: int) -> Tuple[str, int]:
    """读取固定长度的字节片段，返回(hex格式化字符串, 新的offset)"""
    val, offset = read_bytes(data, offset, length)
    return se(val, "bytes"), offset


def se(data, type_str: str) -> str:
    """
    序列化：将Python数据类型转换为字符串表示
    """
    if isinstance(data, int):
        if type_str == "u8":
            if not (0 <= data <= 0xFF):
                raise ValueError(f"u8值超出范围: {data}")
            return f"u8:{data}"
        if type_str == "u16":
            if not (0 <= data <= 0xFFFF):
                raise ValueError(f"u16值超出范围: {data}")
            return f"u16:{data}"
        if type_str == "u32":
            if not (0 <= data <= 0xFFFFFFFF):
                raise ValueError(f"u32值超出范围: {data}")
            return f"u32:{data}"
        if type_str == "i8":
            if not (-128 <= data <= 127):
                raise ValueError(f"i8值超出范围: {data}")
            return f"i8:{data}"
        if type_str == "i16":
            if not (-32768 <= data <= 32767):
                raise ValueError(f"i16值超出范围: {data}")
            return f"i16:{data}"
        if type_str == "i32":
            if not (-2147483648 <= data <= 2147483647):
                raise ValueError(f"i32值超出范围: {data}")
            return f"i32:{data}"

    if type_str == "str" and isinstance(data, str):
        return data

    if type_str == "bytes" and isinstance(data, (bytes, bytearray)):
        return f"bytes:{bytes_to_hex_string(data)}"

    raise ValueError(
        f"类型不匹配或未知类型: type='{type_str}', data={type(data).__name__}"
    )


def de(data: str) -> Tuple[Any, str]:
    """
    反序列化：将字符串转换回Python数据类型
    返回: (value, type_hint) 元组，type_hint是原始类型字符串
    """
    if not isinstance(data, str):
        raise ValueError(f"输入必须是字符串，但得到 {type(data).__name__}")

    # 没有前缀的情况（纯字符串）
    if ":" not in data:
        return data, "str"

    type_prefix, value_str = data.split(":", 1)

    if type_prefix == "u8":
        try:
            val = int(value_str)
            if not (0 <= val <= 0xFF):
                raise ValueError
            return val, "u8"
        except ValueError:
            raise ValueError(f"无效的u8值: {value_str}")

    if type_prefix == "u16":
        try:
            val = int(value_str)
            if not (0 <= val <= 0xFFFF):
                raise ValueError
            return val, "u16"
        except ValueError:
            raise ValueError(f"无效的u16值: {value_str}")

    if type_prefix == "u32":
        try:
            val = int(value_str)
            if not (0 <= val <= 0xFFFFFFFF):
                raise ValueError
            return val, "u32"
        except ValueError:
            raise ValueError(f"无效的u32值: {value_str}")

    if type_prefix == "i8":
        try:
            val = int(value_str)
            if not (-128 <= val <= 127):
                raise ValueError
            return val, "i8"
        except ValueError:
            raise ValueError(f"无效的i8值: {value_str}")

    if type_prefix == "i16":
        try:
            val = int(value_str)
            if not (-32768 <= val <= 32767):
                raise ValueError
            return val, "i16"
        except ValueError:
            raise ValueError(f"无效的i16值: {value_str}")

    if type_prefix == "i32":
        try:
            val = int(value_str)
            if not (-2147483648 <= val <= 2147483647):
                raise ValueError
            return val, "i32"
        except ValueError:
            raise ValueError(f"无效的i32值: {value_str}")

    if type_prefix == "bytes":
        try:
            return bytes.fromhex(value_str), "bytes"
        except ValueError:
            raise ValueError(f"无效的bytes数据: {value_str}")

    # 如果包含冒号但不匹配任何已知类型，仍将其视为字符串
    return data, "str"


def str_to_bytes(
    data: str, byteorder: Literal["little", "big"] = "little", str_encoding=None
) -> bytes:
    """
    将序列化字符串转换为字节序列

    参数:
        data: 序列化字符串，格式如 "u8:16", "u16:1024", "bytes:ff00"
        byteorder: 字节序，'little' 或 'big'，默认小端序
        str_encoding: 字符串编码方式，默认CP932(带NULL)

    返回:
        字节序列
    """

    def encoding_str(data) -> bytes:
        return data.encode("CP932") + b"\x00"

    if str_encoding == None:
        str_encoding = encoding_str

    val, type_prefix = de(data)

    if type_prefix == "u8":
        return val.to_bytes(1, byteorder, signed=False)
    elif type_prefix == "u16":
        return val.to_bytes(2, byteorder, signed=False)
    elif type_prefix == "u32":
        return val.to_bytes(4, byteorder, signed=False)
    elif type_prefix == "i8":
        return val.to_bytes(1, byteorder, signed=True)
    elif type_prefix == "i16":
        return val.to_bytes(2, byteorder, signed=True)
    elif type_prefix == "i32":
        return val.to_bytes(4, byteorder, signed=True)
    elif type_prefix == "bytes":
        return val
    else:
        return str_encoding(data)
