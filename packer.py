#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from pathlib import Path
import struct
import json
import sys

HEADER_SIZE = 0x13880  # 80000
ENTRY_SIZE = 8  # u32 offset + u32 size
NUM_ENTRIES = HEADER_SIZE // ENTRY_SIZE

# 0x634238
TABLE = bytes.fromhex("8B E5 5D C3 A1 E0 30 44 00 85 C0 74 09 5F 5E 33 C0 5B 8B E5 5D C3 8B 45 0C 85 C0 75 14 8B 55 EC 83 C2 20 52 6A 00 E8 F5 28 01 00 83 C4 08 89 45 0C 8B 45 E4 6A 00 6A 00 50 53 FF 15 34 B1 43 00 8B 45 10 85 C0 74 05 8B 4D EC 89 08 8A 45 F0 84 C0 75 78 A1 E0 30 44 00 8B 7D E8 8B 75 0C 85 C0 75 44 8B 1D D0 B0 43 00 85 FF 76 37 81 FF 00 00 04 00 6A 00 76 43 8B 45 F8 8D 55 FC 52 68 00 00 04 00 56 50 FF 15 2C B1 43 00 6A 05 FF D3 A1 E0 30 44 00 81 EF 00 00 04 00 81 C6 00 00 04 00 85 C0 74 C5 8B 5D F8 53 E8 F4 FB FF FF 8B 45 0C 83 C4 04 5F 5E 5B 8B E5 5D C3 8B 55 F8 8D 4D FC 51 57 56 52 FF 15 2C B1 43 00 EB D8 8B 45 E8 83 C0 20 50 6A 00 E8 47 28 01 00 8B 7D E8 89 45 F4 8B F0 A1 E0 30 44 00 83 C4 08 85 C0 75 56 8B 1D D0 B0 43 00 85 FF 76 49 81 FF 00 00 04 00 6A 00 76")


def fix_bytes(data, start, sectionLen, key):
    if not key:
        return
    size = len(key)
    for i in range(sectionLen):
        pos = start + i
        if pos >= len(data):
            break
        b = data[pos] ^ key[i % size]
        data[pos] = b
    return data


def fix_seen_sub(data):
    # https://github.com/satan53x/SExtractor/issues/3#issuecomment-2514255544
    # 0x475BD1
    XOR_TABLE = bytearray.fromhex(
        'BE 32 E2 3F EF 2A 32 08 C6 0C BF 39 2D 47 AE F3')

    pos = 0x20
    OffsetStart = 0x100  # 如果是arc_conv解包需要把此处改为0x100
    start = int.from_bytes(data[pos:pos+4], byteorder='little') + OffsetStart

    key0 = XOR_TABLE
    key1 = XOR_TABLE
    key2 = None

    # 加密区域0
    fix_bytes(data, start, 0x80, key0)
    # 加密区域1
    start += 0x80
    fix_bytes(data, start, 0x81, key1)
    # 加密区域2
    start += 0x81
    fix_bytes(data, start, 0x80, key2)
    return data


def decode_lzss_like(src: bytes, out_size: int) -> bytearray:
    src_i = 0
    n = len(src)
    out = bytearray()

    def need_bytes(k: int):
        if src_i + k > n:
            raise IndexError(
                f"not enough input bytes (need {k}, have {n - src_i})")

    def read_u16_le():
        nonlocal src_i
        need_bytes(2)
        lo = src[src_i]
        hi = src[src_i + 1]
        src_i += 2
        return lo | (hi << 8)

    while True:
        if len(out) >= out_size:
            break

        if src_i >= n:
            break

        control = src[src_i]
        src_i += 1

        for _ in range(8):
            if len(out) >= out_size:
                break

            bit = control & 1
            control >>= 1

            if bit:
                if src_i >= n:
                    raise IndexError(
                        "unexpected end of input while reading literal")
                out.append(src[src_i])
                src_i += 1
            else:
                token = read_u16_le()
                length = (token & 0xF) + 2
                offset = token >> 4

                if offset == 0:
                    raise ValueError("invalid offset 0 in token")

                src_pos = len(out) - offset
                if src_pos < 0:
                    raise IndexError(
                        "back-reference goes before beginning of output")

                for _c in range(length):
                    out.append(out[src_pos])
                    src_pos += 1

    return out


def encode_lzss_like(src: bytes) -> bytes:
    """
    Faster LZSS-like encoder compatible with decode_lzss_like.

    - Window max: 0xFFF (4095)
    - Max match length: 0xF + 2 = 17
    - Token: u16 little-endian: (offset << 4) | (length - 2)
    - Control byte: 8 items per control byte; bit=1 -> literal, bit=0 -> token
    """
    n = len(src)
    if n == 0:
        return b""

    WINDOW_MAX = 0xFFF
    MAX_LEN = 0xF + 2  # 17

    out = bytearray()
    # map 3-byte key -> recent list of positions (keep tail small)
    pos_dict = {}
    POS_LIST_CAP = 64  # cap per key to limit memory & search cost

    i = 0
    # local references for speed
    src_mv = memoryview(src)

    while i < n:
        ctrl_pos = len(out)
        out.append(0)  # placeholder
        control = 0
        bit_mask = 1

        # emit up to 8 items under one control byte
        for _ in range(8):
            if i >= n:
                break

            best_len = 0
            best_off = 0

            # we only build keys for 3-byte sequences to find candidates quickly
            if i + 3 <= n:
                key = bytes(src_mv[i:i+3])  # short immutable key
                lst = pos_dict.get(key)
                if lst:
                    # search recent positions from nearest to farthest
                    max_search_back = i - WINDOW_MAX
                    # iterate reversed to prefer nearer matches
                    for j in reversed(lst):
                        if j < max_search_back:
                            # earlier positions are outside window
                            break
                        # try extend match up to MAX_LEN
                        max_len = min(MAX_LEN, n - i)
                        # compare bytes
                        l = 0
                        # in-Python loop: compare slices is faster when len small, but explicit loop is fine here
                        while l < max_len and src_mv[j + l] == src_mv[i + l]:
                            l += 1
                        if l > best_len and l >= 2:
                            best_len = l
                            best_off = i - j
                            if best_len == MAX_LEN:
                                break

            # decide whether to emit token or literal
            if best_len >= 2:
                token = (best_off << 4) | (best_len - 2)
                out.extend(struct.pack("<H", token))
                # update dictionary for every position inside emitted match
                # this helps future matches; cap lists to POS_LIST_CAP
                for k in range(best_len):
                    p = i + k
                    if p + 3 <= n:
                        kkey = bytes(src_mv[p:p+3])
                        lst = pos_dict.setdefault(kkey, [])
                        lst.append(p)
                        if len(lst) > POS_LIST_CAP:
                            del lst[0]
                i += best_len
            else:
                # literal
                out.append(src_mv[i])
                control |= bit_mask
                # add position for key starting at i
                if i + 3 <= n:
                    kkey = bytes(src_mv[i:i+3])
                    lst = pos_dict.setdefault(kkey, [])
                    lst.append(i)
                    if len(lst) > POS_LIST_CAP:
                        del lst[0]
                i += 1

            bit_mask <<= 1

        out[ctrl_pos] = control

    return bytes(out)


def decode(data: bytes, offset: int, uncompress_size: int) -> bytearray:
    out = bytearray(data)
    n = len(data)

    for i in range(offset, n):
        eax = i - offset

        # 计算 edx = eax & 0x800000FF
        edx = eax & 0x800000FF

        # 如果符号位被设置（bit31），执行 DEC / OR / INC 组合
        if edx & 0x80000000:
            edx = (edx - 1) & 0xFFFFFFFF
            edx |= 0xFFFFFF00
            edx = (edx + 1) & 0xFFFFFFFF

        # base=0，直接取 TABLE[edx]
        dl = TABLE[edx]

        # XOR 解码
        out[i] ^= dl

    new_out = bytearray(out[:offset])
    # 前8个字节是两个u32，即压缩长度和未压缩长度
    # 封包的时候我们需要修改这两个u32
    new_out.extend(decode_lzss_like(out[offset + 0x8:], uncompress_size))
    return new_out


def unpack(input_path: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)

    data = input_path.read_bytes()
    if len(data) < HEADER_SIZE:
        raise AssertionError(
            f"file too small: {len(data)} < header size {HEADER_SIZE}")

    header_blob = data[:HEADER_SIZE]
    body = data[HEADER_SIZE:]

    items = []
    for i in range(NUM_ENTRIES):
        off = i * ENTRY_SIZE
        offset, size = struct.unpack_from("<II", header_blob, off)
        items.append({"offset": offset, "size": size})

    # 断言：offset == 0 时 size 也应为 0
    for idx, it in enumerate(items):
        if it["offset"] == 0:
            assert it["size"] == 0, f"entry {idx} has offset==0 but size!=0 ({it['size']})"

    # 收集非零条目（保留原始顺序）
    nonzero = [it for it in items if it["offset"] != 0]

    # 如果存在非零条目，断言它们紧密贴合：
    # prev.offset + prev.size == next.offset
    for i in range(len(nonzero) - 1):
        a = nonzero[i]
        b = nonzero[i + 1]
        if a["offset"] + a["size"] != b["offset"]:
            raise AssertionError(
                f"non-zero items not tightly packed at nonzero-index {i}: "
                f"prev.offset(0x{a['offset']:X}) + prev.size(0x{a['size']:X}) = 0x{(a['offset'] + a['size']):X} != next.offset(0x{b['offset']:X})"
            )

    # 可选断言：第一个非零块是否从 header 末尾开始
    if nonzero:
        first = nonzero[0]
        if first["offset"] != HEADER_SIZE:
            # 不是必须的断言，但通常期望如此。只做 warning，不强制退出。
            print(
                f"warning: first non-zero offset != HEADER_SIZE (0x{HEADER_SIZE:X}) -> 0x{first['offset']:X}", file=sys.stderr)

    # 解包：依序写为 1.snr, 2.snr, ...
    file_idx = 1
    for it in items:
        if it["offset"] == 0:
            continue
        offset = it["offset"]
        size = it["size"]
        # 确认文件体包含这段数据
        if offset + size > len(data):
            raise AssertionError(
                f"entry points outside file: offset(0x{offset:X}) + size(0x{size:X}) > filelen(0x{len(data):X})"
            )
        chunk = data[offset:offset + size]
        # 注意，我们封包的时候，需要更新这些数据，我们假设文件头（即[:offset]这一段长度不会变化，只有内容区长度会变化）
        decode_offset,  uncompress_size, compress_size = struct.unpack_from(
            "<III", chunk, 0x20)
        out_file = out_dir / f"{file_idx}.snr"
        out_file.write_bytes(fix_seen_sub(
            decode(chunk, decode_offset, uncompress_size)))
        print(f"wrote {out_file} (size={size})")
        file_idx += 1

    # 保存 header metadata，供 pack 使用
    meta_path = out_dir / "_header.json"
    meta_path.write_text(json.dumps(items, indent=2, ensure_ascii=False))
    print(f"wrote header metadata to {meta_path}")
    print("unpack done.")


def pack(input_dir: Path, out_path: Path):

    meta_path = input_dir / "_header.json"
    if not meta_path.exists():
        raise FileNotFoundError(
            f"expected metadata file '_header.json' in {input_dir}; run unpack first to produce it.")

    items = json.loads(meta_path.read_text())

    if len(items) != NUM_ENTRIES:
        raise AssertionError(
            f"header item count mismatch: {len(items)} != {NUM_ENTRIES}")

    # 准备输出 header（will fill shortly）和 body segments
    body_segments = []
    current_offset = HEADER_SIZE
    next_input_index = 1  # 从 1.snr 开始为第一个非零条目

    # 计算并填充新的 offset/size（保留 offset==0 的条目为 0/0）
    new_items = []
    # Count nonzero headers to check files presence
    nonzero_count = sum(1 for it in items if it["offset"] != 0)

    for it_idx, it in enumerate(items):
        if it["offset"] == 0:
            new_items.append({"offset": 0, "size": 0})
            continue

        in_file = input_dir / f"{next_input_index}.snr"
        if not in_file.exists():
            raise FileNotFoundError(
                f"expected file {in_file} for non-zero header entry #{next_input_index} (header index {it_idx})")

        decoded = fix_seen_sub(bytearray(in_file.read_bytes()))
        # 读取 decode_offset/uncompress_size/old_compress_size（在偏移 0x20）
        if len(decoded) < 0x20 + 12:
            raise AssertionError(
                f"{in_file} too small to contain header fields at 0x20")

        decode_offset, old_uncompress_size, old_compress_size = struct.unpack_from(
            "<III", decoded, 0x20)

        if decode_offset > len(decoded):
            raise AssertionError(
                f"{in_file}: decode_offset ({decode_offset}) > file length ({len(decoded)})")

        header_part = bytearray(decoded[:decode_offset])  # 假设 header 长度不会改变
        uncompressed_body = decoded[decode_offset:]  # 这是解压之后的原始数据
        uncompress_size = len(uncompressed_body)

        # 压缩
        compressed = encode_lzss_like(uncompressed_body)
        compressed_length = len(compressed) + 0x8  # 包括两个u32

        # 更新 header_part 中的字段
        struct.pack_into("<II", header_part, 0x20 + 4,
                         uncompress_size, compressed_length)

        # 在 decode_offset 处写入两个 u32（compressed_length, uncompress_size），然后写入 compressed 数据
        out_chunk = bytearray()
        out_chunk.extend(header_part)
        out_chunk.extend(struct.pack(
            "<II", compressed_length, uncompress_size))
        out_chunk.extend(compressed)

        # 对 out_chunk 从 decode_offset 开始进行表XOR（与 decode 中相同的算法，XOR 可逆）
        n = len(out_chunk)
        for i in range(decode_offset, n):
            eax = i - decode_offset
            edx = eax & 0x800000FF
            if edx & 0x80000000:
                edx = (edx - 1) & 0xFFFFFFFF
                edx |= 0xFFFFFF00
                edx = (edx + 1) & 0xFFFFFFFF
            dl = TABLE[edx]
            out_chunk[i] ^= dl

        # 最终 chunk 就是 out_chunk
        chunk_bytes = bytes(out_chunk)
        size = len(chunk_bytes)
        offset = current_offset
        new_items.append({"offset": offset, "size": size})
        body_segments.append(chunk_bytes)
        current_offset += size
        print(f"packing {in_file.name} -> offset=0x{offset:X} size={size} (compressed_body={compressed_length} uncompressed={uncompress_size})")
        next_input_index += 1

    # After iterating, we should have consumed exactly nonzero_count files
    if next_input_index - 1 != nonzero_count:
        raise AssertionError(
            f"number of input files ({next_input_index - 1}) does not match non-zero header entries ({nonzero_count})"
        )

    # 构造 header bytes（小端）
    header_bytes = bytearray()
    for it in new_items:
        header_bytes += struct.pack("<II", it["offset"], it["size"])

    if len(header_bytes) != HEADER_SIZE:
        raise AssertionError(
            f"constructed header size mismatch: {len(header_bytes)} != {HEADER_SIZE}")

    # 写出最终文件：header + concatenated body
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("wb") as f:
        f.write(header_bytes)
        for seg in body_segments:
            f.write(seg)

    print(
        f"wrote packed file to {out_path} (total size {out_path.stat().st_size} bytes)")
    print("pack done.")


def main():
    ap = argparse.ArgumentParser(
        description="packer 解包/打包工具")
    sub = ap.add_subparsers(dest='cmd', required=True)
    ap_unpack = sub.add_parser('unpack', help='解包')
    ap_unpack.add_argument('-i', '--input', required=True, help='输入 (SEEN 文件)')
    ap_unpack.add_argument('-o', '--out', required=True, help='输出目录')
    ap_pack = sub.add_parser('pack', help='打包')
    ap_pack.add_argument('-i', '--input', required=True,
                         help='输入目录 (unpack 产生的目录)')
    ap_pack.add_argument('-o', '--out', required=True, help='输出文件 (SEEN)')
    args = ap.parse_args()
    if args.cmd == 'unpack':
        unpack(Path(args.input), Path(args.out))
    elif args.cmd == 'pack':
        pack(Path(args.input), Path(args.out))


if __name__ == '__main__':
    main()
