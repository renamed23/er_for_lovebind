#!/usr/bin/env python3

from typing import Any, Callable, Dict, List, Literal, Tuple, Union

from utils_tools.libs.translate_lib import (
    bytes_to_hex_string,
    de,
    read_bytes_s,
    read_i8_s,
    read_i16_s,
    read_i32_s,
    read_str_s,
    read_u8_s,
    read_u16_s,
    read_u32_s,
    se,
    str_to_bytes,
)

# ==========================================
# 处理器类（用于链式调用）
# ==========================================


class Handler:
    def __init__(self, func):
        self.func = func

    def __call__(self, data, offset, ctx):
        return self.func(data, offset, ctx)

    def repeat(self, count):
        return Handler(repeat_handler(self.func, count))

    def repeat_var(self, var_index=-1):
        return Handler(repeat_var_handler(self.func, var_index))

    def args(self, *a):
        return Handler(args_handler(self.func, *a))


# ==========================================
# 装饰器
# ==========================================


def repeat_handler(handler: Callable, count: int) -> Callable:
    def wrapped_handler(data: bytes, offset: int, ctx: Dict) -> Tuple[List[Any], int]:
        results = []
        current_offset = offset

        for _ in range(count):
            result, current_offset = handler(data, current_offset, ctx)
            results.append(result)

        return results, current_offset

    return wrapped_handler


def repeat_var_handler(handler: Callable, var_index: int = -1) -> Callable:
    def wrapped_handler(data: bytes, offset: int, ctx: Dict) -> Tuple[List[Any], int]:
        # 从上下文中获取重复次数
        count_value = ctx["value"][var_index]
        # 如果值形如 "u32:5"，提取数字部分
        if isinstance(count_value, str) and ":" in count_value:
            count = int(count_value.split(":", 1)[1])
        else:
            raise ValueError(f"非法的 count_value: {count_value}")

        results = []
        current_offset = offset

        for _ in range(count):
            result, current_offset = handler(data, current_offset, ctx)
            results.append(result)

        return results, current_offset

    return wrapped_handler


def args_handler(handler: Callable, *handler_args) -> Callable:
    def wrapped_handler(data: bytes, offset: int, ctx: Dict) -> Tuple[Any, int]:
        return handler(data, offset, ctx, *handler_args)

    return wrapped_handler


# ==========================================
# 普通处理器
# ==========================================


def u8_handler(data: bytes, offset: int, ctx: Dict) -> Tuple[str, int]:
    return read_u8_s(data, offset)


def u16_handler(data: bytes, offset: int, ctx: Dict) -> Tuple[str, int]:
    return read_u16_s(data, offset)


def u32_handler(data: bytes, offset: int, ctx: Dict) -> Tuple[str, int]:
    return read_u32_s(data, offset)


def i8_handler(data: bytes, offset: int, ctx: Dict) -> Tuple[str, int]:
    return read_i8_s(data, offset)


def i16_handler(data: bytes, offset: int, ctx: Dict) -> Tuple[str, int]:
    return read_i16_s(data, offset)


def i32_handler(data: bytes, offset: int, ctx: Dict) -> Tuple[str, int]:
    return read_i32_s(data, offset)


def string_handler(data: bytes, offset: int, ctx: Dict) -> Tuple[str, int]:
    return read_str_s(data, offset)


# ==========================================
# 终止处理器
# ==========================================


class EndParsing(Exception):
    pass


def end_handler(data: bytes, offset: int, ctx: Dict) -> Tuple[str, int]:
    raise EndParsing()


# ==========================================
# 参数化处理器 (带参数)
# ==========================================


def byte_slice_handler(
    data: bytes, offset: int, ctx: Dict, length: int
) -> Tuple[str, int]:
    return read_bytes_s(data, offset, length)


# ==========================================
# 处理器实例
# ==========================================


u8 = Handler(u8_handler)
u16 = Handler(u16_handler)
u32 = Handler(u32_handler)
i8 = Handler(i8_handler)
i16 = Handler(i16_handler)
i32 = Handler(i32_handler)
string = Handler(string_handler)
byte_slice = Handler(byte_slice_handler)
end = Handler(end_handler)


# ==========================================
# 解析引擎
# ==========================================


def parse_data(
    debug_info: dict, data: bytes, flatten_opcodes_map: Dict
) -> Tuple[List[Dict], int]:
    opcodes = []
    cur_offset = 0
    total_len = len(data)

    # 按键长度降序排序
    sorted_keys = sorted(flatten_opcodes_map.keys(), key=len, reverse=True)

    while cur_offset < total_len:
        try:
            matched = False
            start_offset = cur_offset

            for signature in sorted_keys:
                if data.startswith(signature, cur_offset):
                    # 找到匹配项
                    handlers = flatten_opcodes_map[signature]
                    new_offset = cur_offset + len(signature)

                    # 构建 Opcode 对象
                    op_hex = bytes_to_hex_string(signature)
                    cur_op = {
                        "op": op_hex,
                        "offset": start_offset,
                        "index": len(opcodes),
                        "value": [],
                    }

                    # 执行处理链
                    param_offset = new_offset
                    try:
                        for handler in handlers:
                            res, param_offset = handler(data, param_offset, cur_op)

                            if res != None:
                                if isinstance(res, list):
                                    cur_op["value"].extend(res)
                                else:
                                    cur_op["value"].append(res)
                    except EndParsing:
                        opcodes.append(cur_op)
                        return opcodes, param_offset

                    opcodes.append(cur_op)
                    cur_offset = param_offset
                    matched = True
                    break

            if not matched:
                unknown_byte = data[cur_offset]
                print(
                    f"{debug_info['file_name']}: 未知 Opcode {hex(unknown_byte)} 在 {hex(cur_offset + debug_info['offset'])}"
                )
                break
        except Exception as e:
            op = data[cur_offset]
            print(
                f"{debug_info['file_name']}: 处理 Opcode {hex(op)} 在 {hex(cur_offset + debug_info['offset'])} 发生错误 {e}"
            )
            break

    return opcodes, cur_offset


# ==========================================
# 辅助函数
# ==========================================


def h(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def flat(opcodes_map: Dict) -> Dict:
    flat_opcodes_map = {}

    def flatten_opcodes(prefix: bytes, op_map: Dict):
        for key, value in op_map.items():
            if isinstance(key, bytes):  # 是子opcode
                new_key = prefix + key

                if isinstance(value, dict):  # 继续嵌套
                    flatten_opcodes(new_key, value)
                else:  # 是处理器列表
                    flat_opcodes_map[new_key] = value
            elif key == "default" and prefix:  # 处理default情况
                flat_opcodes_map[prefix] = value

    # 处理顶层opcodes
    for key, value in opcodes_map.items():
        if isinstance(value, dict):
            flatten_opcodes(key, value)
        else:
            flat_opcodes_map[key] = value

    return flat_opcodes_map


def assemble_one_op(
    op_entry: Dict, byteorder: Literal["little", "big"] = "little", str_encoding=None
) -> bytes:
    """
    将一条反汇编后的 OP JSON 转换为二进制
    """
    out = bytearray()

    # 1. opcode 本身
    # "00 03" -> bytes
    op_bytes = bytes.fromhex(op_entry["op"])
    out += op_bytes

    # 2. 参数顺序拼接
    for item in op_entry.get("value", []):
        out += str_to_bytes(item, byteorder, str_encoding)

    return bytes(out)


def fix_offset(
    file: str, opcodes: Dict, old2new: Dict[int, int], fix_ops_map: Dict
) -> Dict:
    """
    修复操作码中的偏移，将旧偏移映射为新偏移
    """
    for op in opcodes:
        op_key = op["op"]
        if op_key not in fix_ops_map:
            continue

        indices_spec = fix_ops_map[op_key]

        # 支持列表或回调函数
        if callable(indices_spec):
            indices = indices_spec(op)
        else:
            indices = indices_spec

        for i in indices:  # type: ignore
            old_offset, type_hint = de(op["value"][i])
            if old_offset not in old2new:
                raise ValueError(f"{file}, {op} 指向不存在的 offset: {old_offset}")
            op["value"][i] = se(old2new[old_offset], type_hint)

    return opcodes
