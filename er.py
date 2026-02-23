#!/usr/bin/env python3

# 说明：从 https://github.com/arcusmaximus/VNTranslationTools 由AI生成

import json
import os
import struct
import io
import argparse
import re
from typing import List, Dict, Tuple, Optional, Any
from utils_tools.libs import translate_lib


# =============================================================================
# 基础工具类
# =============================================================================


class BinaryReader:
    """二进制读取辅助类"""

    def __init__(self, stream: io.BytesIO):
        self.stream = stream

    def read_byte(self) -> int:
        b = self.stream.read(1)
        return b[0] if b else 0

    def peek_byte(self) -> int:
        pos = self.stream.tell()
        b = self.stream.read(1)
        self.stream.seek(pos)
        return b[0] if b else 0

    def read_uint16(self) -> int:
        data = self.stream.read(2)
        return struct.unpack('<H', data)[0] if len(data) == 2 else 0

    def read_int32(self) -> int:
        data = self.stream.read(4)
        return struct.unpack('<i', data)[0] if len(data) == 4 else 0

    def read_bytes(self, count: int) -> bytes:
        return self.stream.read(count)


class BinaryWriter:
    """二进制写入辅助类"""

    def __init__(self, stream: io.BytesIO):
        self.stream = stream

    def write_byte(self, val: int):
        self.stream.write(bytes([val & 0xFF]))

    def write_uint16(self, val: int):
        self.stream.write(struct.pack('<H', val))

    def write_int32(self, val: int):
        self.stream.write(struct.pack('<i', val))

    def write_bytes(self, data: bytes):
        self.stream.write(data)


class RealLiveAssembler:
    """负责将文本重新编码为二进制数据"""

    def __init__(self):
        self.stream = io.BytesIO()
        self.writer = BinaryWriter(self.stream)

    def get_bytes(self) -> bytes:
        return self.stream.getvalue()

    def write_string(self, text: str, quote: bool):
        encoded = text.encode('CP932')
        if not quote:
            self.writer.write_bytes(encoded)
            return

        self.writer.write_byte(ord('"'))
        i = 0
        while i < len(encoded):
            c = encoded[i]
            i += 1
            if c == ord('"'):
                self.writer.write_byte(ord('\\'))
                self.writer.write_byte(ord('"'))
            else:
                self.writer.write_byte(c)
                # Check if lead byte (Shift-JIS)
                if (0x81 <= c <= 0x9F) or (0xE0 <= c <= 0xFC):
                    if i < len(encoded):
                        self.writer.write_byte(encoded[i])
                        i += 1
        self.writer.write_byte(ord('"'))

    def write_line_break(self):
        # 写入换行符调用: #3, 201, 0, 0 (模块 3, 函数 201)
        self.write_function_call(0, 3, 201, 0, 0)

    def write_function_call(self, type_: int, module: int, function: int, num_args: int, overload: int):
        self.writer.write_byte(ord('#'))
        self.writer.write_byte(type_)
        self.writer.write_byte(module)
        self.writer.write_uint16(function)
        self.writer.write_uint16(num_args)
        self.writer.write_byte(overload)


# =============================================================================
# 核心逻辑类
# =============================================================================

class RealLiveFile:
    """
    封装 RealLive 脚本文件的处理逻辑：
    1. 解析结构 (Disassemble)
    2. 提取文本
    3. 替换文本并重建文件 (Repack)
    4. 自动修复指针偏移 (Fix Offsets)
    """

    # 引擎特征常量
    GOTO_FUNCTIONS = {
        0x01: [0x0000, 0x0001, 0x0002, 0x0005, 0x0006, 0x0007, 0x0010],
        0x05: [0x0001, 0x0002, 0x0005, 0x0006, 0x0007]
    }
    PARAMETERLESS_GOTO_FUNCTIONS = {
        0x01: [0x0000, 0x0005],
        0x05: [0x0001, 0x0005]
    }
    GOTO_ON_FUNCTIONS = {
        0x01: [0x0003, 0x0008],
        0x05: [0x0003, 0x0008]
    }
    GOTO_CASE_FUNCTIONS = {
        0x01: [0x0004, 0x0009],
        0x05: [0x0004, 0x0009]
    }
    MESSAGE_FUNCTIONS = {
        0x03: [0x0070]
    }
    SCENE_END_MARKER = bytes([
        0x82, 0x72, 0x82, 0x85, 0x82, 0x85, 0x82, 0x8E, 0x82, 0x64, 0x82, 0x8E,
        0x82, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    ])
    SELECT_MODULE = 0x02

    def __init__(self, file_path: str):
        self.file_path = file_path
        with open(file_path, 'rb') as f:
            self.data = f.read()

        self.stream = io.BytesIO(self.data)
        self.reader = BinaryReader(self.stream)

        # 解析头信息
        self.stream.seek(8)
        self.line_numbers_offset = self.reader.read_int32()
        self.stream.seek(0x20)
        self.code_offset = self.reader.read_int32()

        # 分析结果存储
        self.address_encountered: List[int] = []  # 存储指针出现的文件偏移
        # (offset, length, type)
        self.text_ranges: List[Tuple[int, int, str]] = []

        # 内部状态
        self.current_module = None
        self.current_function = None

        # 初始化时执行分析
        self._disassemble()

    def get_text_blocks(self) -> List[Dict[str, Any]]:
        """提取所有文本块"""
        results = []
        dialogue_regex = re.compile(r'^【(.+?)】(.+)$')

        for offset, length, _ in self.text_ranges:
            raw_bytes = self.data[offset:offset+length]
            text = raw_bytes.decode('CP932')

            if not text.strip():
                continue

            match = dialogue_regex.match(text)
            if match:
                results.append({
                    "name": match.group(1),
                    "message": match.group(2)
                })
            else:
                results.append({
                    "message": text
                })
        return results

    def repack(self, translations: List[Dict[str, str]], trans_idx, output_path: str):
        """
        使用译文重建文件并自动修复偏移
        :param translations: 译文列表 [{'name': '...', 'message': '...'}, ...]
        :param output_path: 输出文件路径
        """
        print("开始打包...")
        new_stream = io.BytesIO()
        writer = BinaryWriter(new_stream)

        chunks = []
        last_pos = 0

        sorted_ranges = sorted(self.text_ranges, key=lambda x: x[0])

        for range_offset, range_len, _ in sorted_ranges:
            # 1. 写入之前的原始数据
            if range_offset > last_pos:
                chunks.append(
                    {'type': 'raw', 'old_start': last_pos, 'len': range_offset - last_pos})

            # 2. 检查原始内容是否有效（跳过空文本或无法解码的）
            orig_bytes = self.data[range_offset:range_offset+range_len]

            decoded = orig_bytes.decode('CP932')
            if not decoded.strip():
                chunks.append(
                    {'type': 'raw', 'old_start': range_offset, 'len': range_len})
                last_pos = range_offset + range_len
                continue

            # 3. 获取译文
            if trans_idx >= len(translations):
                raise ValueError("译文数量不足")

            item = translations[trans_idx]
            trans_idx += 1

            # 4. 编码新文本
            new_bytes = self._encode_message(
                item.get('name'), item.get('message', ''))
            chunks.append({'type': 'new', 'old_start': range_offset,
                          'len': range_len, 'data': new_bytes})
            last_pos = range_offset + range_len

        # 尾部数据
        if last_pos < len(self.data):
            chunks.append({'type': 'raw', 'old_start': last_pos,
                          'len': len(self.data) - last_pos})

        # 写入新流并建立映射表
        chunk_map = []  # (old_end_exclusive, shift)
        current_new_pos = 0

        for chunk in chunks:
            old_start = chunk['old_start']
            shift = current_new_pos - old_start
            chunk_map.append((old_start + chunk['len'], shift))

            if chunk['type'] == 'raw':
                writer.write_bytes(
                    self.data[old_start: old_start + chunk['len']])
                current_new_pos += chunk['len']
            else:
                writer.write_bytes(chunk['data'])
                current_new_pos += len(chunk['data'])

        # 修复指针和头部
        new_data = bytearray(new_stream.getvalue())
        self._fix_pointers(new_data, chunk_map)

        with open(output_path, 'wb') as f:
            f.write(new_data)
        print(f"文件已保存至: {output_path}")

        return trans_idx

    # --- 内部核心方法 ---

    def _disassemble(self):
        """遍历整个脚本，标记文本和指针位置"""
        self.stream.seek(self.code_offset)
        while self._read_opcode():
            pass

    def _read_opcode(self) -> bool:
        opcode_byte = self.reader.read_byte()
        if opcode_byte == 0:
            return False
        opcode = chr(opcode_byte)

        if opcode == '\0':
            return False
        elif opcode == '\n':
            self.reader.read_uint16()
            return True
        elif opcode in ['!', '@']:
            self._read_kidoku_flag()
            return True
        elif opcode in [',', '?']:
            return True
        elif opcode == '#':
            self._read_function_call()
            return True
        elif opcode == '$':
            self._read_expression()
            return True
        elif opcode in ['\\', 'a']:
            self.reader.read_byte()
            return True
        elif opcode == '(':
            self.stream.seek(self.stream.tell() - 1)
            self._read_item_list('(', ')')
            return True
        elif opcode == '{':
            self.stream.seek(self.stream.tell() - 1)
            self._read_item_list('{', '}')
            return True
        elif opcode == '"':
            self.stream.seek(self.stream.tell() - 1)
            self._read_quoted_string()
            return True
        else:
            self.stream.seek(self.stream.tell() - 1)
            self._read_unquoted_string()
            return True

    def _read_kidoku_flag(self):
        line_number_index = self.reader.read_uint16()
        pos = self.stream.tell()
        target_pos = self.line_numbers_offset + 4 * line_number_index
        self.stream.seek(target_pos)
        line_number = self.reader.read_int32() - 1000000
        if line_number >= 0:
            entry_point_offset = 0x34 + line_number * 4
            self.address_encountered.append(entry_point_offset)
        self.stream.seek(pos)

    def _read_function_call(self):
        type_ = self.reader.read_byte()
        self.current_module = self.reader.read_byte()
        self.current_function = self.reader.read_uint16()
        num_args = self.reader.read_uint16()
        overload = self.reader.read_byte()

        is_paramless_goto = self._check_func(self.PARAMETERLESS_GOTO_FUNCTIONS)
        if not is_paramless_goto and chr(self.reader.peek_byte()) == '(':
            self._read_item_list('(', ')')

        if self._check_func(self.GOTO_FUNCTIONS):
            self._read_pointer()
        elif self._check_func(self.GOTO_ON_FUNCTIONS):
            if chr(self.reader.read_byte()) != '{':
                raise ValueError("Invalid Data")
            for _ in range(num_args):
                self._read_pointer()
            if chr(self.reader.read_byte()) != '}':
                raise ValueError("Invalid Data")
        elif self._check_func(self.GOTO_CASE_FUNCTIONS):
            self._read_item_list('{', '}', self._read_goto_case_item)
        elif self.current_module == self.SELECT_MODULE:
            self._read_select()

        self.current_module = None
        self.current_function = None

    def _check_func(self, func_dict):
        if self.current_module in func_dict:
            return self.current_function in func_dict[self.current_module]
        return False

    def _read_pointer(self):
        self.address_encountered.append(self.stream.tell())
        self.reader.read_int32()

    def _read_goto_case_item(self):
        self._read_item_list('(', ')')
        self._read_pointer()

    def _read_select(self):
        if chr(self.reader.peek_byte()) == '{':
            self._read_item_list('{', '}', self._read_select_item)

    def _read_select_item(self):
        self._skip_debug_markers()
        if chr(self.reader.peek_byte()) == '(':
            self.reader.read_byte()
            if chr(self.reader.peek_byte()) == '(':
                self._read_item_list('(', ')')
            self.reader.read_byte()
            while chr(self.reader.peek_byte()) != ')':
                self._read_opcode()
            self.reader.read_byte()
        self._read_string()
        self._skip_debug_markers()

    def _read_expression(self):
        variable = self.reader.read_byte()
        if variable == 0xC8:
            return
        if variable == 0xFF:
            self.reader.read_int32()
            return
        self._read_item_list('[', ']')

    def _read_item_list(self, open_char, close_char, item_reader=None):
        if item_reader is None:
            item_reader = self._read_opcode
        c = chr(self.reader.read_byte())
        if c != open_char:
            raise ValueError(f"Expected {open_char}")
        while True:
            c = chr(self.reader.peek_byte())
            if c == close_char:
                self.reader.read_byte()
                return
            item_reader()

    def _read_string(self):
        if chr(self.reader.peek_byte()) == '"':
            self._read_quoted_string()
        else:
            self._read_unquoted_string()

    def _read_quoted_string(self):
        start_pos = self.stream.tell()
        if chr(self.reader.read_byte()) != '"':
            raise ValueError("Expected quote")
        while True:
            b = self.reader.read_byte()
            if chr(b) == '\\':
                self.reader.read_byte()
            elif (0x81 <= b <= 0x9F) or (0xE0 <= b <= 0xFC):
                self.reader.read_byte()
            elif chr(b) == '"':
                break
        end_pos = self.stream.tell()
        if self.current_function is None or self._check_func(self.MESSAGE_FUNCTIONS):
            self.text_ranges.append((start_pos, end_pos - start_pos, 'msg'))

    def _read_unquoted_string(self):
        start_pos = self.stream.tell()
        special_chars = "\0\n!@,?#$\\a(){}[]"
        while True:
            b = self.reader.read_byte()
            if chr(b) in special_chars:
                self.stream.seek(self.stream.tell() - 1)
                break
            if (0x81 <= b <= 0x9F) or (0xE0 <= b <= 0xFC):
                self.reader.read_byte()
        end_pos = self.stream.tell()

        is_scene_end = False
        if (end_pos - start_pos) == len(self.SCENE_END_MARKER):
            self.stream.seek(start_pos)
            if self.reader.read_bytes(len(self.SCENE_END_MARKER)) == self.SCENE_END_MARKER:
                is_scene_end = True
            self.stream.seek(end_pos)

        if (self.current_function is None or self._check_func(self.MESSAGE_FUNCTIONS)) and not is_scene_end:
            self.text_ranges.append((start_pos, end_pos - start_pos, 'msg'))

    def _skip_debug_markers(self):
        while chr(self.reader.peek_byte()) == '\n':
            self._read_opcode()

    def _fix_pointers(self, new_data: bytearray, chunk_map: List[Tuple[int, int]]):
        """修复所有跳转指令的地址"""

        def get_shift(addr):
            for end, shift in chunk_map:
                if addr < end:
                    return shift
            return chunk_map[-1][1] if chunk_map else 0

        print(f"正在修复 {len(self.address_encountered)} 个指针...")

        # 1. 断言 CodeOffset 不会变化
        code_shift = get_shift(self.code_offset)
        assert code_shift == 0

        # 2. 修复所有跳转指针
        for old_ptr_loc in self.address_encountered:
            # 指针本身在新文件中的位置
            loc_shift = get_shift(old_ptr_loc)
            new_ptr_loc = old_ptr_loc + loc_shift

            # 读取旧值 (Relative Address)
            old_rel_val = struct.unpack(
                '<i', self.data[old_ptr_loc:old_ptr_loc+4])[0]

            # 转绝对地址 -> 计算位移 -> 转回相对地址
            old_abs_addr = old_rel_val + self.code_offset
            target_shift = get_shift(old_abs_addr)
            new_abs_addr = old_abs_addr + target_shift
            new_rel_val = new_abs_addr - self.code_offset

            new_data[new_ptr_loc:new_ptr_loc +
                     4] = struct.pack('<i', new_rel_val)

    def _encode_message(self, name: Optional[str], message: str) -> bytes:
        assembler = RealLiveAssembler()
        if name:
            assembler.write_string(f"【{name}】", False)

        lines = message.splitlines()
        for idx, line in enumerate(lines):
            if not line:
                continue
            assembler.write_string(line, True)
            if idx < len(lines) - 1:
                assembler.write_line_break()
        return assembler.get_bytes()


# =============================================================================
# 外部调用函数 (对应 API)
# =============================================================================

def extract_strings(path: str, output_file: str):
    files = translate_lib.collect_files(path, 'snr')
    results = []
    for file in files:
        processor = RealLiveFile(file)
        results.extend(processor.get_text_blocks())
    print(f"提取了 {len(results)} 项")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)


def replace_strings(path: str, text_file: str, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    with open(text_file, 'r', encoding='utf-8') as f:
        text = json.load(f)
    files = translate_lib.collect_files(path, 'snr')
    trans_index = 0
    for file in files:
        rel_path = os.path.relpath(file, start=path)
        out_path = os.path.join(output_dir, rel_path)
        processor = RealLiveFile(file)
        trans_index = processor.repack(text, trans_index, out_path)
        print(f"已处理: {file}")
    if trans_index != len(text):
        print(f"错误: 有 {len(text)} 项译文，但只消耗了 {trans_index}。")
        exit(1)

# ---------------- main ----------------


def main():
    parser = argparse.ArgumentParser(description='文件提取和替换工具')
    subparsers = parser.add_subparsers(
        dest='command', help='功能选择', required=True)

    ep = subparsers.add_parser('extract', help='解包文件提取文本')
    ep.add_argument('--path', required=True, help='文件夹路径')
    ep.add_argument('--output', default='raw.json', help='输出JSON文件路径')

    rp = subparsers.add_parser('replace', help='替换解包文件中的文本')
    rp.add_argument('--path', required=True, help='文件夹路径')
    rp.add_argument('--text', default='translated.json', help='译文JSON文件路径')
    rp.add_argument('--output-dir', default='translated',
                    help='输出目录(默认: translated)')

    args = parser.parse_args()
    if args.command == 'extract':
        extract_strings(args.path, args.output)
        print(f"提取完成! 结果保存到 {args.output}")
    elif args.command == 'replace':
        replace_strings(args.path, args.text, args.output_dir)
        print(f"替换完成! 结果保存到 {args.output_dir} 目录")


if __name__ == '__main__':
    main()
