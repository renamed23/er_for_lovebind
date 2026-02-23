#!/usr/bin/env python3

import argparse
import json
import sys
from pathlib import Path

# --- 常量定义 ---

# 标点符号去重映射
PUNCT_REPLACEMENTS = [
    ("……", "…"),
    ("――", "―"),
    ("——", "—"),
    ("‥‥", "‥"),
    ("──", "─"),
]

# 普通同义词替换
SYNONYM_REPLACEMENTS = [
    ("真是", "真"),
    ("什么", "啥"),
    ("那一个", "那个"),
    ("哪一个", "哪个"),
    ("某一个", "某个"),
    ("每一个", "每个"),
    ("是一种", "是种"),
    ("这一部分", "这部分"),
    ("是一个", "是个"),
    ("有一个", "有个"),
    ("是一名", "是名"),
    ("是一位", "是位"),
    ("是一件", "是件"),
    ("一个人", "一人"),
    ("两个人", "两人"),
    ("三个人", "三人"),
    ("的时候", "时"),
    ("之前", "前"),
    ("之后", "后"),
    ("之时", "时"),
    ("如果", "若"),
]

# 句末特定标点
ENDS_WITH_PUNCTS = ("」", "。", "！", "？", "!", "?")

# 激进同义词替换
AGGRESSIVE_SYNONYM_REPLACEMENTS = [
    ("但是", "但"),
    ("可是", "可"),
    ("因为", "因"),
    ("已经", "已"),
    ("知道", "知"),
    ("不要", "别"),
    ("非常", "很"),
]

# 激进修复："的"字结构
DE_REPLACEMENTS = [
    ("我的", "我"),
    ("你的", "你"),
    ("他的", "他"),
    ("她的", "她"),
    ("它的", "它"),
    ("我们的", "我们"),
    ("你们的", "你们"),
    ("他们的", "他们"),
]

# 激进修复：语气词
MODAL_PARTICLES = ("呢", "吗", "吧", "啊", "呀", "啦", "哦", "哟", "呦")

# 激进修复：完全删除的标点
AGGRESSIVE_PUNCT_REMOVAL = set(
    ["…", "―", "—", "‥", "~", "～", "·", "・", "，", ",", "、", " "]
)

# --- 辅助功能 ---


def build_full_width_map():
    """构建全角到半角的转换表"""
    table = {}
    # 0-9
    for i in range(10):
        table[0xFF10 + i] = 0x30 + i
    # A-Z
    for i in range(26):
        table[0xFF21 + i] = 0x41 + i
    # a-z
    for i in range(26):
        table[0xFF41 + i] = 0x61 + i
    return table


FULL_WIDTH_MAP = build_full_width_map()


def get_encoding_name(enc_type):
    """将枚举字符串转换为 Python 的编码名称"""
    if enc_type.lower() in ["cp932", "shiftjis", "shift_jis"]:
        return "cp932"
    if enc_type.lower() == "gbk":
        return "gbk"

    print(f"未知编码 {enc_type}")
    exit(1)


def pseudo_byte_len(text):
    """
    模拟的字节长度
    ASCII (<= 0x7F) 算 1，其他算 2
    """
    length = 0
    for char in text:
        if ord(char) <= 0x7F:
            length += 1
        else:
            length += 2
    return length


def real_byte_len(text, encoding):
    """真实编码字节长度（用于原文在 Pseudo 模式下的计算）"""
    try:
        return len(text.encode(encoding, errors="replace"))
    except LookupError:
        print(f"错误: 未知的编码 '{encoding}'")
        sys.exit(1)


def count_len_orig(text, method, encoding):
    """计算原文长度：Pseudo 模式下用真实编码长度"""
    if method == "chars":
        return len(text)
    elif method == "pseudo":
        return real_byte_len(text, encoding)
    return len(text)


def count_len_trans(text, method):
    """计算译文长度：Pseudo 模式下用模拟长度"""
    if method == "chars":
        return len(text)
    elif method == "pseudo":
        return pseudo_byte_len(text)
    return len(text)


def full_width_to_half_width(text):
    return text.translate(FULL_WIDTH_MAP)


def try_fix_message(trans_msg, orig_len, method, aggressive):
    """
    尝试修复消息长度
    返回: (modified_text, is_fixed)
    """
    modified = trans_msg

    # 辅助内部函数：检查是否达标
    def check():
        return count_len_trans(modified, method) <= orig_len

    # 初始检查
    if check():
        return modified, True

    # --- 第1阶段：标准化处理 ---
    # 1. 全角转半角
    if method == "pseudo":
        modified = full_width_to_half_width(modified)
        if check():
            return modified, True

    # 2. 删除全角空格
    modified = modified.replace("　", "")
    if check():
        return modified, True

    # 3. 合并重复标点
    for src, dst in PUNCT_REPLACEMENTS:
        if src in modified:
            while src in modified:
                modified = modified.replace(src, dst)
            if check():
                return modified, True

    # --- 第2阶段：轻度缩减 ---
    # 4. 同义词替换
    for src, dst in SYNONYM_REPLACEMENTS:
        if src in modified:
            modified = modified.replace(src, dst)
            if check():
                return modified, True

    # 5. 删除末尾标点
    if modified.endswith(ENDS_WITH_PUNCTS):
        while modified.endswith(ENDS_WITH_PUNCTS):
            modified = modified[:-1]
            if check():
                return modified, True
        if check():
            return modified, True

    # 如果非激进模式，到此结束
    if not aggressive:
        return modified, False

    # --- 第3阶段：激进修复 ---
    modified, fixed = try_aggressive_fix(modified, orig_len, method)
    return modified, fixed


def try_aggressive_fix(trans_msg, orig_len, method):
    """激进修复逻辑"""
    modified = trans_msg

    def check():
        return count_len_trans(modified, method) <= orig_len

    if check():
        return modified, True

    # 1. 激进同义词
    for src, dst in AGGRESSIVE_SYNONYM_REPLACEMENTS:
        modified = modified.replace(src, dst)
    if check():
        return modified, True

    # 2. 删除 "的" 字所有格
    for src, dst in DE_REPLACEMENTS:
        modified = modified.replace(src, dst)
    if check():
        return modified, True

    # 3. 删除所有 "的"
    modified = modified.replace("的", "")
    if check():
        return modified, True

    # 4. 删除空白字符
    modified = "".join(c for c in modified if not c.isspace())
    if check():
        return modified, True

    # 5. 删除结尾语气词
    while modified.endswith(MODAL_PARTICLES):
        for p in MODAL_PARTICLES:
            if modified.endswith(p):
                modified = modified[: -len(p)]
        if check():
            return modified, True

    if check():
        return modified, True

    # 6. 删除特定标点
    modified = "".join(c for c in modified if c not in AGGRESSIVE_PUNCT_REMOVAL)

    return modified, check()


def is_length_unbounded(item):
    """检查 length_unbounded 字段"""
    val = item.get("length_unbounded")
    return val is True


# --- 主程序 ---


def main():
    parser = argparse.ArgumentParser(
        description="检查译文 message 长度并在超长时写入 error 字段（支持自动修复）"
    )
    parser.add_argument(
        "--orig", "-o", required=True, type=Path, help="原文 JSON 文件路径"
    )
    parser.add_argument(
        "--trans", "-t", required=True, type=Path, help="译文 JSON 文件路径"
    )
    parser.add_argument(
        "--method", "-m", choices=["pseudo", "chars"], default="pseudo", help="比较方法"
    )
    parser.add_argument(
        "--behave",
        "-b",
        choices=["check", "fix", "aggressive-fix"],
        default="check",
        help="行为模式",
    )
    parser.add_argument(
        "--encoding", default="CP932", help="目标编码 (CP932, ShiftJIS, GBK)"
    )

    args = parser.parse_args()

    # 准备环境
    encoding_name = get_encoding_name(args.encoding)
    aggressive = args.behave == "aggressive-fix"
    do_fix = args.behave in ["fix", "aggressive-fix"]

    # 读取文件
    try:
        with open(args.orig, "r", encoding="utf-8") as f:
            orig_json = json.load(f)
        with open(args.trans, "r", encoding="utf-8") as f:
            trans_json = json.load(f)
    except Exception as e:
        print(f"读取或解析 JSON 文件失败: {e}")
        sys.exit(1)

    if not isinstance(orig_json, list) or not isinstance(trans_json, list):
        print("错误: JSON 顶层必须是数组")
        sys.exit(1)

    if len(orig_json) != len(trans_json):
        print(f"错误: 数组长度不一致 (原文: {len(orig_json)}, 译文: {len(trans_json)})")
        sys.exit(1)

    error_count = 0
    fixed_count = 0
    skipped_count = 0

    for i, (orig_item, trans_item) in enumerate(zip(orig_json, trans_json)):
        # 检查跳过标志
        if is_length_unbounded(orig_item):
            if "error" in trans_item:
                print(
                    f"第 {i} 项: 跳过检查（length_unbounded=true），移除已有的 error 字段"
                )
                del trans_item["error"]
            else:
                print(f"第 {i} 项: 跳过检查（length_unbounded=true）")
            skipped_count += 1
            continue

        orig_msg = orig_item.get("message", "")
        trans_msg = trans_item.get("message", "")

        # 计算原文长度
        orig_len_val = orig_item.get("message_orig_len")
        if orig_len_val is not None and isinstance(orig_len_val, (int, float)):
            orig_len = int(orig_len_val)
        else:
            orig_len = count_len_orig(orig_msg, args.method, encoding_name)

        # 译文长度
        trans_len = count_len_trans(trans_msg, args.method)

        if trans_len > orig_len:
            if args.behave == "check":
                err_text = f"原文 {orig_len} < 译文 {trans_len}"
                trans_item["error"] = err_text
                error_count += 1
                print(
                    f"第 {i} 项: 插入 error 字段（原:{orig_len} 译:{trans_len}）",
                    file=sys.stderr,
                )

            elif do_fix:
                # 尝试修复
                fixed_msg, is_fixed = try_fix_message(
                    trans_msg, orig_len, args.method, aggressive
                )

                # 更新 message
                trans_item["message"] = fixed_msg
                new_len = count_len_trans(fixed_msg, args.method)

                if is_fixed:
                    if "error" in trans_item:
                        del trans_item["error"]
                    fixed_count += 1
                    if aggressive:
                        print(
                            f"第 {i} 项: 激进修复成功（原:{orig_len} 修后:{new_len}）",
                            file=sys.stderr,
                        )
                    else:
                        print(
                            f"第 {i} 项: 自动修复成功（原:{orig_len} 修后:{new_len}）",
                            file=sys.stderr,
                        )
                else:
                    # 修复失败
                    err_text = f"原文 {orig_len} < 译文 {new_len}" + (
                        "（激进修复后仍超长）" if aggressive else ""
                    )
                    trans_item["error"] = err_text
                    error_count += 1
                    if aggressive:
                        print(
                            f"第 {i} 项: 激进修复后仍超长（原:{orig_len} 修后:{new_len}）",
                            file=sys.stderr,
                        )
                    else:
                        print(
                            f"第 {i} 项: 插入 error 字段（原:{orig_len} 译:{new_len}）",
                            file=sys.stderr,
                        )

        else:
            # 长度正常，移除旧的 error
            if "error" in trans_item:
                print(
                    f"第 {i} 项: 移除已有的 error 字段（原:{orig_len} 译:{trans_len}）",
                    file=sys.stderr,
                )
                del trans_item["error"]

    # 确定输出路径
    output_path = args.trans
    if do_fix:
        # 如果是修复模式，添加 _modified 后缀
        output_path = args.trans.with_name(
            f"{args.trans.stem}_modified{args.trans.suffix}"
        )

    # 写入文件
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(trans_json, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"写入文件失败: {e}")
        sys.exit(1)

    # 最终报告
    if args.behave == "check":
        if error_count > 0:
            print(
                f"已写回 {output_path}（已标注 {error_count} 项超长，跳过 {skipped_count} 项）。"
            )
        else:
            print(
                f"检查成功：未发现超长译文，文件已写回（清除可能存在的 error 字段，跳过 {skipped_count} 项）。"
            )
    elif args.behave == "fix":
        if fixed_count > 0:
            print(
                f"已自动修复 {fixed_count} 项超长译文，输出到: {output_path}（跳过 {skipped_count} 项）"
            )

        if error_count > 0:
            print(f"仍有 {error_count} 项无法自动修复，需要人工处理。")
        else:
            print(
                f"所有超长译文已自动修复，输出到: {output_path}（跳过 {skipped_count} 项）"
            )
    elif args.behave == "aggressive-fix":
        total_processed = fixed_count + error_count
        if total_processed > 0:
            print(
                f"已激进修复 {total_processed} 项超长译文（其中 {fixed_count} 项完全修复，{error_count} 项修复后仍超长），输出到: {output_path}（跳过 {skipped_count} 项）"
            )
        else:
            print(
                f"无需激进修复，文件已输出到: {output_path}（跳过 {skipped_count} 项）"
            )


if __name__ == "__main__":
    main()
