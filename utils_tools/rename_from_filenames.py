#!/usr/bin/env python3

import os
import sys
import uuid
from pathlib import Path

cwd = Path.cwd()
raw = cwd / "raw"
lines = [
    l.strip() for l in (cwd / "filenames.txt").read_text(encoding="utf-8").splitlines()
]
if not lines:
    sys.exit("ERROR: filenames.txt 空")

# 验证目标基名
for i, name in enumerate(lines, 1):
    if (
        not name
        or name in (".", "..")
        or (os.path.sep in name)
        or (os.path.altsep and os.path.altsep in name)
    ):
        sys.exit(f"ERROR: 第{i}行非法目标名: {name}")
if len(set(lines)) != len(lines):
    sys.exit("ERROR: 发现重复目标名")

n = len(lines)
src_paths = [raw / f"{i}.snr" for i in range(1, n + 1)]
for p in src_paths:
    if not p.exists() or not (p.is_file() or p.is_symlink()):
        sys.exit(f"ERROR: 缺失或非法源文件: {p}")

dst_paths = [raw / f"{name}" for name in lines]
src_set = set(src_paths)
# 不允许运行时覆盖非源文件
for dst in dst_paths:
    if dst.exists() and dst not in src_set:
        sys.exit(f"ERROR: 目标已存在且不是源文件，可能覆盖: {dst}")

# 处理循环冲突：先把被占用的源移动到临时名


def gen_tmp():
    while True:
        t = raw / (".tmp_rename_" + uuid.uuid4().hex)
        if not t.exists():
            return t


mapping = dict(zip(src_paths, dst_paths))
temp_map = {}
need = [s for s, d in mapping.items() if s.resolve() != d.resolve()]
for s in need:
    d = mapping[s]
    if d in src_set and d not in temp_map and d != s:
        tmp = gen_tmp()
        d.rename(tmp)
        temp_map[d] = tmp

# 逐条重命名除已临时化的源
for s, dst in mapping.items():
    if s in temp_map:
        continue
    if s.resolve() == dst.resolve():
        continue
    s.rename(dst)

# 把临时文件回填到最终目标
for orig_src, tmp in temp_map.items():
    final = mapping[orig_src]
    if final.exists():
        sys.exit(f"ERROR: 预期空的目标已存在: {final}")
    tmp.rename(final)

print("OK")
