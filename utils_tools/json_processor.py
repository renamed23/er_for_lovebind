#!/usr/bin/env python3

import json
import sys
from typing import Any, Dict, List, Optional, Tuple


class JSONProcessor:
    def __init__(self, file_path: str, mode: str):
        self.file_path = file_path
        self.mode = mode
        self.data = None

        # 定义标记映射关系：字段名 -> 标记字符串
        self.tag_mappings = {
            "is_select": "[select]",
            "is_title": "[title]",
        }

        # 定义处理函数映射 - 可以方便地扩展
        self.process_functions = {
            "e": [
                # self.check_and_mark_whitespace,
                # self.remove_fullwidth_spaces,
                # self.escape_backslashes,
                self.add_tags_based_on_fields,
            ],
            "r": [
                self.remove_tags_based_on_fields,
                self.add_white_space,
                self.replace_rare_characters,
                self.replace_nested_brackets,
                self.replace_quotation_marks,
                # self.mapping_gbk_unsupport_emoji,
                # self.unescape_backslashes
            ],
        }

    def load_json(self) -> List[Dict]:
        """加载JSON文件"""
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"加载文件 {self.file_path} 时出错: {str(e)}")
            sys.exit(1)

    def save_json(self) -> None:
        """保存JSON文件"""
        try:
            with open(self.file_path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"保存文件 {self.file_path} 时出错: {str(e)}")
            sys.exit(1)

    def check_and_mark_whitespace(self, item: Dict) -> None:
        """e阶段：如果message以全角空格开头，设置need_whitespace为True并移除该空格"""
        message = item.get("message", "")
        if isinstance(message, str) and message.startswith("　"):
            item["need_whitespace"] = True

    def add_white_space(self, item: Dict) -> None:
        if "need_whitespace" in item and item["need_whitespace"] is True:
            message = item["message"]
            if not message.startswith("　"):
                item["message"] = "　" + message

    def add_tags_based_on_fields(self, item: Dict) -> None:
        """e阶段：根据布尔字段在message字段前添加相应的标记"""
        message = item.get("message", "")
        original_message = message

        # 检查所有标记字段
        for field, tag in self.tag_mappings.items():
            if field in item and item[field] is True:
                # 检查是否已经添加了标记
                if not message.startswith(tag):
                    message = tag + message
                    print(f"  添加标记: 在message字段前添加了{tag} (基于字段 {field})")
                else:
                    print(
                        f"  跳过添加标记: message字段已以{tag}开头 (基于字段 {field})"
                    )

        # 只有在消息被修改时才更新
        if message != original_message:
            item["message"] = message
            print(f"    原始消息: {original_message}")
            print(f"    处理后消息: {message}")

    def remove_tags_based_on_fields(self, item: Dict) -> None:
        """r阶段：根据布尔字段移除message字段开头的相应标记"""
        message = item.get("message", "")
        original_message = message

        for field, tag in self.tag_mappings.items():
            if field in item and item[field] is True:
                # 检查message是否以标记开头
                if message.startswith(tag):
                    # 移除开头的标记
                    message = message[len(tag):]
                    print(
                        f"  移除标记: 成功移除了message字段开头的{tag} (基于字段 {field})"
                    )
                else:
                    # 如果应该移除但没有找到标记，报错
                    print(f"  错误: {field}字段为True，但message字段未以{tag}开头")
                    print(f"    当前message: {message}")
                    print(f"  处理中断: 在条目中发现不一致的标记")
                    sys.exit(1)

        # 只有在消息被修改时才更新
        if message != original_message:
            item["message"] = message
            print(f"    原始消息: {original_message}")
            print(f"    处理后消息: {message}")

    def replace_rare_characters(self, item: Dict) -> None:
        """将生僻词映射为BMP字符的代替词"""

        # 生僻词到BMP代替词的映射表
        rare_char_map = {
            "𫚕鱼": "季鱼",
            "𬶮鱼": "宗鱼",
        }

        # 检查是否有需要处理的字段
        for field in ["message", "name"]:
            if field in item and isinstance(item[field], str):
                text_before = item[field]

                # 执行所有映射替换
                for rare_char, replacement in rare_char_map.items():
                    if rare_char in text_before:
                        # 统计替换次数
                        count = text_before.count(rare_char)

                        # 执行替换
                        item[field] = item[field].replace(
                            rare_char, replacement)

                        # 更新text_before，以便后续检查
                        text_before = item[field]

                        # 打印替换日志
                        print(
                            f"  处理生僻词替换: 将 {rare_char} 替换为 {replacement}，共 {count} 处"
                        )

                # 如果有替换发生，显示替换前后的对比
                if text_before != item[field]:
                    print(f"    字段 '{field}' 替换前: {text_before}")
                    print(f"    字段 '{field}' 替换后: {item[field]}")

    def replace_quotation_marks(self, item: Dict) -> None:
        """将message字段中的〝替换为『，〟替换为』"""
        if "message" in item and isinstance(item["message"], str):
            # 统计替换的次数
            before = item["message"]

            # 执行替换
            item["message"] = item["message"].replace(
                "〝", "『").replace("〟", "』")

            # 如果发生了替换，打印日志
            if before != item["message"]:
                count_left = before.count("〝")
                count_right = before.count("〟")
                print(f"  处理引号替换: 替换了 {count_left} 个〝和 {count_right} 个〟")
                print(f"    原文本: {before}")
                print(f"    新文本: {item['message']}")

    def replace_nested_brackets(self, item: Dict) -> None:
        """自动将嵌套的「」替换为『』"""
        if "message" in item and isinstance(item["message"], str):
            item["message"] = self.process_nested_brackets(item["message"])

        if "name" in item and isinstance(item["name"], str):
            item["name"] = self.process_nested_brackets(item["name"])

    def mapping_gbk_unsupport_emoji(self, item: Dict) -> None:
        """将GBK不支持的字符映射为支持的字符"""
        # 字符映射规则
        char_map = {"〜": "～", "・": "·", "♪": "～", "♥": "～", "♡": "～"}

        # 处理字段列表
        for field in ["message", "name"]:
            if field in item and isinstance(item[field], str):
                before = item[field]
                for old_char, new_char in char_map.items():
                    if old_char in before:
                        item[field] = item[field].replace(old_char, new_char)

    def process_nested_brackets(self, text: str) -> str:
        """处理文本中的嵌套括号，将内层的「」替换为『』"""
        if "「" not in text and "」" not in text:
            return text

        # 使用栈来跟踪括号层级
        stack = []
        result_chars = list(text)
        changes_made = 0

        for i, char in enumerate(text):
            if char == "「":
                # 压栈：记录位置和层级
                stack.append((i, len(stack) + 1))  # (位置, 层级)
            elif char == "」":
                if stack:
                    start_pos, level = stack.pop()
                    # 如果层级大于1，说明是嵌套的，需要替换
                    if level > 1:
                        # 替换开括号
                        if result_chars[start_pos] == "「":
                            result_chars[start_pos] = "『"
                            changes_made += 1
                        # 替换闭括号
                        if result_chars[i] == "」":
                            result_chars[i] = "』"
                            changes_made += 1

        result = "".join(result_chars)

        # 如果有修改，打印日志（可选）
        if changes_made > 0:
            print(f"  处理嵌套括号: 替换了 {changes_made} 对括号")
            print(f"    原文本: {text}")
            print(f"    新文本: {result}")

        return result

    def remove_fullwidth_spaces(self, item: Dict) -> None:
        """删除name和message字段中的全角空格"""
        if "message" in item and isinstance(item["message"], str):
            # 真正删除全角空格，而不是替换
            item["message"] = item["message"].replace("　", "")  # 删除全角空格

        if "name" in item and isinstance(item["name"], str):
            item["name"] = item["name"].replace("　", "")  # 删除全角空格

    def escape_backslashes(self, item: Dict) -> None:
        """将\\转义为@"""
        if "message" in item and isinstance(item["message"], str):
            item["message"] = item["message"].replace("\\", "@")

        if "name" in item and isinstance(item["name"], str):
            item["name"] = item["name"].replace("\\", "@")

    def unescape_backslashes(self, item: Dict) -> None:
        """将@转义回\\"""
        if "message" in item and isinstance(item["message"], str):
            item["message"] = item["message"].replace("@", "\\")

        if "name" in item and isinstance(item["name"], str):
            item["name"] = item["name"].replace("@", "\\")

    def process(self) -> None:
        """执行处理流程"""
        # 加载数据
        self.data = self.load_json()

        # 检查模式是否有效
        if self.mode not in self.process_functions:
            print(f"错误: 不支持的模式 '{self.mode}'")
            print(f"支持的模式: {list(self.process_functions.keys())}")
            sys.exit(1)

        # 获取该模式下要执行的处理函数
        functions = self.process_functions[self.mode]

        # 对每个条目应用处理函数
        processed_count = 0
        for item in self.data:
            for func in functions:
                func(item)
            processed_count += 1

        # 保存处理后的数据
        self.save_json()

        print(f"处理完成! 模式: {self.mode}, 文件: {self.file_path}")
        print(f"处理了 {processed_count} 个条目，执行了 {len(functions)} 个处理函数")
        print(f"当前支持的标记类型: {list(self.tag_mappings.keys())}")


def main():
    if len(sys.argv) != 3:
        print("用法: python json_processor.py <模式:e/r> <json文件路径>")
        print("示例:")
        print("  python json_processor.py e data.json  # 转义模式")
        print(
            "  python json_processor.py r data.json  # 反转义模式（自动处理嵌套括号）"
        )
        sys.exit(1)

    mode = sys.argv[1]
    file_path = sys.argv[2]

    # 创建处理器并执行
    processor = JSONProcessor(file_path, mode)
    processor.process()


if __name__ == "__main__":
    main()
