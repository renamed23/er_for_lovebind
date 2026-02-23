#!/usr/bin/env python3

"""
简洁版：按原文长度截断译文（ASCII=1, 其他=2），保护指定 token。
忽略 length_unbounded 为 true 的条目。
直接在顶部修改配置，运行即可。若无法在不删保护 token 的前提下降到原长，将抛错并退出。
"""

import json
import sys
from typing import List, Tuple

# ===== 配置区（手动修改） =====
RAW_PATH = "raw.json"
TRANS_PATH = "generated/translated.json"
OUT_PATH = "generated/translated.json"
IGNORE_TOKENS = ["@p", "@k", "@r"]  # 保护 token 列表
CASE_INSENSITIVE = True
CODE_PAGE = "cp932"
# ==============================


def orig_byte_len(s: str) -> int:
    """
    将原文以 CODE_PAGE 编码，返回真实字节长度。
    """
    b = s.encode(CODE_PAGE)
    return len(b)


def calc_len(s: str) -> int:
    return sum(1 if ord(ch) < 128 else 2 for ch in s)


def find_trailing_token_run(s: str, tokens: List[str], case_ins: bool) -> int:
    """
    返回尾部连续保护 token-run 的总长度（以 codepoint 计）。
    例如 s='abc@r@r' 且 tokens=['@r'] -> 返回 4（两个 '@r' 各占 2 个 codepoint）。
    不修改原字符串，匹配顺序按 tokens 的顺序（可按需在调用处先按长度降序排序 tokens）。
    """
    if not s:
        return 0
    s_cmp = s.lower() if case_ins else s
    pos = len(s_cmp)
    run_len = 0
    while pos > 0:
        matched = False
        # 尝试匹配任一 token 作为当前尾部（按 tokens 顺序匹配）
        for t in tokens:
            if not t:
                continue
            t_cmp = t.lower() if case_ins else t
            tlen = len(t_cmp)
            if pos >= tlen and s_cmp[pos - tlen : pos] == t_cmp:
                run_len += tlen
                pos -= tlen
                matched = True
                break
        if not matched:
            break
    return run_len


def truncate_preserve_tokens(
    s: str, limit: int, tokens: List[str], case_ins: bool
) -> str:
    """若可以截断到 <= limit 返回新字符串；若不可能则抛 ValueError。"""
    cur = s
    if calc_len(cur) <= limit:
        return cur

    # 主循环：每次只检测一次尾部 token-run
    while calc_len(cur) > limit:
        run_len = find_trailing_token_run(cur, tokens, case_ins)
        if run_len > 0:
            # cur 末尾有一段连续的保护 token-run（长度为 run_len）
            if len(cur) <= run_len:
                # 整串只剩保护 token-run，无法再删
                raise ValueError(
                    "无法在不删除保护 token 的前提下继续截断（字符串仅剩保护 token）。"
                )
            # 删除 token-run 之前的最后一个 codepoint（绝不触碰 token-run 内部）
            idx = len(cur) - run_len - 1
            cur = cur[:idx] + cur[idx + 1 :]
        else:
            # 末尾没有保护 token，常规删除最后一个 codepoint
            cur = cur[:-1]
        # 注意：下一轮循环会重新计算 calc_len(cur) 并再次检测尾部 token-run

    return cur


def is_length_unbounded(item: dict) -> bool:
    """
    检查条目是否设置了 length_unbounded 为 true。
    只接受布尔值 true，其他值（包括字符串 "true"）都视为 false。
    """
    return item.get("length_unbounded") is True


def process_all(raw_list: list, trans_list: list) -> list:
    if len(raw_list) != len(trans_list):
        raise ValueError(
            f"长度不一致：原文 {len(raw_list)} 项，译文 {len(trans_list)} 项。"
        )
    out = []
    for idx, (o, t) in enumerate(zip(raw_list, trans_list)):
        # 要求结构一致：如果原文有 name/ message，则译文必须有
        for key in ("name", "message"):
            if key in o and key not in t:
                raise ValueError(
                    f"第 {idx} 项结构不一致：原文有字段 '{key}'，译文缺失。"
                )
        new_t = dict(t)

        # 检查是否跳过截断
        if is_length_unbounded(o):
            # 跳过该条目的所有截断处理
            out.append(new_t)
            continue

        for key in ("name", "message"):
            if key not in o:
                continue
            orig = o.get(key) or ""
            trans = t.get(key) or ""

            # 优先使用译文中的 orig_len 字段
            orig_len_field = f"{key}_orig_len"
            if orig_len_field in t:
                orig_len = t[orig_len_field]
            else:
                try:
                    orig_len = orig_byte_len(orig)
                except UnicodeEncodeError as e:
                    raise ValueError(
                        f"第 {idx} 项字段 '{key}' 的原文无法用 {CODE_PAGE} 编码：{e}"
                    )

            if calc_len(trans) <= orig_len:
                continue
            # 需要截断
            try:
                new_val = truncate_preserve_tokens(
                    trans, orig_len, IGNORE_TOKENS, CASE_INSENSITIVE
                )
            except ValueError as e:
                # 报错时附带上下文便于定位
                raise ValueError(
                    f"第 {idx} 项字段 '{key}' 无法截断到原文长度 (原长={orig_len}，译长={calc_len(trans)})；原因：{e}"
                )
            new_t[key] = new_val
        out.append(new_t)
    return out


def main():
    try:
        with open(RAW_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
        with open(TRANS_PATH, "r", encoding="utf-8") as f:
            trans = json.load(f)
    except Exception as e:
        print("读取 JSON 失败：", e, file=sys.stderr)
        sys.exit(1)

    try:
        out = process_all(raw, trans)
    except Exception as e:
        print("处理失败：", e, file=sys.stderr)
        sys.exit(2)

    out_path = TRANS_PATH
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print("写入失败：", e, file=sys.stderr)
        sys.exit(3)

    print(f"完成：处理 {len(raw)} 项，输出 -> {out_path}")


if __name__ == "__main__":
    main()
