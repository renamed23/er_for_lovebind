#!/usr/bin/env python3

import argparse
import json
from collections import deque
from enum import Enum
from pathlib import Path


# -----------------------------
# 编码类型
# -----------------------------
class EncodingType(Enum):
    CP932 = "cp932"
    SHIFT_JIS = "shift_jis"
    GBK = "gbk"

    def contains_char(self, ch: str) -> bool:
        """检查字符是否能被该编码表示"""
        if ch.isascii():
            return True
        try:
            ch.encode(self.value)
            return True
        except UnicodeEncodeError:
            return False

    def suggested_ranges(self):
        """建议的替身字符范围（用于生成池）"""
        if self in (EncodingType.CP932, EncodingType.SHIFT_JIS):
            return [
                (0x3041, 0x3096),  # 平假名
                (0x30A1, 0x30FA),  # 片假名
                (0x30FD, 0x30FE),  # ヽ-ヾ
                (0x31F0, 0x31FF),  # 片假名扩展
                (0x4E00, 0x9FFF),  # CJK统一汉字
                (0x3400, 0x4DBF),  # CJK扩展A
            ]
        else:
            return [
                (0x4E00, 0x9FFF),  # CJK统一汉字
                (0x3400, 0x4DBF),  # CJK扩展A
                (0x2000, 0x206F),  # 常用标点
                (0x3000, 0x303F),  # CJK符号和标点
            ]

    def code_page(self) -> int:
        if self in (EncodingType.CP932, EncodingType.SHIFT_JIS):
            return 932
        else:
            return 936


# -----------------------------
# 替身池
# -----------------------------
class ReplacementPool:
    def __init__(self, encoding: EncodingType, pool_chars: list[str]):
        self.encoding = encoding
        self.pool = pool_chars
        self.free = deque(pool_chars)
        self.orig_to_repl = {}
        self.repl_to_orig = {}

    @staticmethod
    def load(path: Path) -> "ReplacementPool":
        data = json.loads(path.read_text(encoding="utf-8"))
        encoding = EncodingType(data["encoding"])
        pool = data["pool"]

        # 校验字符是否可编码
        invalid = [c for c in pool if not encoding.contains_char(c)]
        if invalid:
            raise ValueError(f"替身池中包含不可编码字符: {invalid}")

        return ReplacementPool(encoding, pool)

    def save(self, path: Path):
        data = {
            "encoding": self.encoding.value,
            "pool": self.pool,
        }
        path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def get(self, orig: str) -> str:
        """为原字符分配替身"""
        if orig in self.orig_to_repl:
            return self.orig_to_repl[orig]

        if not self.free:
            raise RuntimeError(f"替身池已耗尽，无法为 '{orig}' 分配替身")

        repl = self.free.popleft()
        self.orig_to_repl[orig] = repl
        self.repl_to_orig[repl] = orig
        return repl

    def map_text(self, text: str) -> str:
        """将文本映射为目标编码可用的文本"""
        out = []
        for ch in text:
            if self.encoding.contains_char(ch):
                out.append(ch)
            else:
                out.append(self.get(ch))
        return "".join(out)

    def write_mapping(self, path: Path):
        """写出 替身 -> 原字符 映射表"""
        data = {
            "code_page": self.encoding.code_page(),
            "mapping": self.repl_to_orig,
        }
        path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )


# -----------------------------
# 替身池生成
# -----------------------------
def generate_pool(paths: list[Path], output: Path, encoding: EncodingType):
    pool = set()

    # 根据编码范围生成候选字符
    for start, end in encoding.suggested_ranges():
        for code in range(start, end + 1):
            ch = chr(code)
            if encoding.contains_char(ch):
                pool.add(ch)

    # 剔除文本中已存在的字符
    for path in paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        for item in data:
            if "name" in item and item["name"]:
                pool.difference_update(item["name"])
            pool.difference_update(item["message"])

    # 按码点从大到小排序
    pool_chars = sorted(pool, reverse=True)

    ReplacementPool(encoding, pool_chars).save(output)
    print(f"成功生成替身池，字符数: {len(pool_chars)}")
    print(f"保存到: {output}")


# -----------------------------
# 文本映射
# -----------------------------
def map_text(paths: list[Path], output_dir: Path, pool_path: Path):
    pool = ReplacementPool.load(pool_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    for path in paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        for item in data:
            if "name" in item and item["name"]:
                item["name"] = pool.map_text(item["name"])
            item["message"] = pool.map_text(item["message"])

        out_path = output_dir / path.name
        out_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    pool.write_mapping(output_dir / "mapping.json")
    print("处理完成")
    print(f"输出目录: {output_dir}")
    print("字符映射表: mapping.json")


# -----------------------------
# CLI
# -----------------------------
def collect_json_files(paths: list[str]) -> list[Path]:
    files = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            files.extend(path.rglob("*.json"))
        else:
            files.append(path)
    return files


def main():
    parser = argparse.ArgumentParser(
        description="将 JSON 文本中不兼容编码的字符映射为替身字符"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_map = sub.add_parser("map", help="映射文本")
    p_map.add_argument("--path", required=True, nargs="+")
    p_map.add_argument("--output", default="./replaced/")
    p_map.add_argument("--replacement-pool", default="replacement_pool.json")

    p_gen = sub.add_parser("generate-pool", help="生成替身池")
    p_gen.add_argument("--path", required=True, nargs="+")
    p_gen.add_argument("--output", default="replacement_pool.json")
    p_gen.add_argument(
        "--encoding",
        choices=[e.value for e in EncodingType],
        default=EncodingType.CP932.value,
    )

    args = parser.parse_args()
    files = collect_json_files(args.path)

    if args.cmd == "map":
        map_text(
            files,
            Path(args.output),
            Path(args.replacement_pool),
        )
    else:
        generate_pool(
            files,
            Path(args.output),
            EncodingType(args.encoding),
        )


if __name__ == "__main__":
    main()
