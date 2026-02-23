#!/usr/bin/env python3

import json
import re
import sys
from typing import Any, Callable, Dict, List, Tuple


class JSONChecker:
    def __init__(self, original_json: List[Dict], translated_json: List[Dict]):
        self.original = original_json
        self.translated = translated_json
        self.errors = []

        # 字符正则表达式
        self.korean_pattern = re.compile(r"[ㄱ-ㅎㅏ-ㅣ가-힣]")
        # 日语平假名：U+3040-U+309F
        self.hiragana_pattern = re.compile(r"[\u3040-\u309F]")
        # 日语片假名：U+30A0-U+30FF
        self.katakana_pattern = re.compile(r"[\u30A0-\u30FF]")
        # 定义要检查的特殊字符
        self.special_chars = ["@p", "@k", "@r", "@P", "@K", "@R"]

        # 定义禁用词列表
        self.forbidden_words = [
            "学长",  # 统一为前辈
            "学姐",
            "学弟",  # 统一为后辈
            "学妹",
            "酱",  # 使用'小XX'而不是'XX酱'
            "肉刃",
            "桑",
            "甬道",
            "妳",  # 使用'你'
            "name",
            "dst",
            "message",
            ":",
            "甫",  # 使用 '刚' 或者 '刚刚'
        ]

        # 最大消息字符长度
        self.max_text_len = 128

        # 不可见字符正则表达式（包括零宽度空格、连接符、格式控制符等）
        self.invisible_pattern = re.compile(
            r"[\u200B-\u200F\u2060-\u2064\u206A-\u206F\uFEFF\u202A-\u202E\u180E\u2063]"
        )

        # 不可见字符映射表，用于显示字符名称
        self.invisible_char_names = {
            "\u200b": "U+200B(零宽度空格)",
            "\u200c": "U+200C(零宽度非连接符)",
            "\u200d": "U+200D(零宽度连接符)",
            "\u200e": "U+200E(左至右标记)",
            "\u200f": "U+200F(右至左标记)",
            "\u2060": "U+2060(单词连接符)",
            "\u2061": "U+2061(函数应用)",
            "\u2062": "U+2062(不可见乘号)",
            "\u2063": "U+2063(不可见分隔符)",
            "\u2064": "U+2064(不可见加号)",
            "\u206a": "U+206A(不可见乘号变体)",
            "\u206b": "U+206B(不可见乘号变体)",
            "\ufeff": "U+FEFF(零宽度不换行空格/字节顺序标记)",
            "\u202a": "U+202A(左至右嵌入)",
            "\u202b": "U+202B(右至左嵌入)",
            "\u202c": "U+202C(弹出方向格式化)",
            "\u202d": "U+202D(左至右覆盖)",
            "\u202e": "U+202E(右至左覆盖)",
            "\u180e": "U+180E(蒙古文元音分隔符)",
        }

        # 注册所有检查方法
        self.checks = [
            # self.check_special_characters,
            self.check_korean_characters,
            self.check_japanese_characters,
            # self.check_duplicate_quotes,
            # self.check_length_discrepancy,
            # self.check_quote_consistency,
            self.check_invisible_characters,
            # self.check_forbidden_words,
            # self.check_unpaired_quotes,  # 新增：检查未配对的引号
            # self.check_max_text_len,
        ]

    def check_max_text_len(self) -> bool:
        """检查译文的最大长度"""
        success = True

        for i, tran in enumerate(self.translated):
            msg = tran["message"]

            if len(msg) > self.max_text_len:
                self.errors.append(
                    f"索引 {i} message字段超长 {msg} ({len(msg)} > {self.max_text_len})"
                )
                success = False

        return success

    def check_unpaired_quotes(self) -> bool:
        """检查译文中是否有未配对的「」、『』、以及“”"""
        success = True

        # 配对规则
        open_to_close = {
            "「": "」",
            "『": "』",
            "“": "”",
            "‘": "’",
            "（": "）",
        }
        close_to_open = {v: k for k, v in open_to_close.items()}

        for i, tran in enumerate(self.translated):
            if "message" not in tran:
                continue

            message = tran["message"]
            has_error = False
            error_details = []

            stack: list[tuple[str, int]] = []

            # 第一遍：配对检查
            for pos, char in enumerate(message):
                # 开引号
                if char in open_to_close:
                    stack.append((char, pos))

                # 闭引号
                elif char in close_to_open:
                    if stack and stack[-1][0] == close_to_open[char]:
                        stack.pop()
                    else:
                        has_error = True
                        error_details.append(f"位置 {pos}: 多余的 '{char}'")

            # 剩余未关闭的开引号
            for quote_char, pos in stack:
                has_error = True
                error_details.append(f"位置 {pos}: 未关闭的 '{quote_char}'")

            if not has_error:
                continue

            success = False
            self.errors.append(f"索引 {i} 译文中存在未配对的引号:")

            for detail in error_details:
                self.errors.append(f"  {detail}")

            # 高亮显示
            highlighted = list(message)

            # 标记未关闭的开引号
            for quote_char, pos in stack:
                highlighted[pos] = f"【{quote_char}】"

            # 第二遍：标记多余的闭引号
            temp_stack = []
            for pos, char in enumerate(message):
                if char in open_to_close:
                    temp_stack.append(char)
                elif char in close_to_open:
                    if temp_stack and temp_stack[-1] == close_to_open[char]:
                        temp_stack.pop()
                    else:
                        highlighted[pos] = f"【{char}】"

            highlighted_text = "".join(highlighted)

            self.errors.append(
                f"  原文message: {self.original[i].get('message', '无')}"
            )
            self.errors.append(f"  译文message: {message}")
            self.errors.append(f"  高亮显示: {highlighted_text}")
            self.errors.append("")

        return success

    def check_forbidden_words(self) -> bool:
        """检查译文中是否包含禁用词"""
        success = True

        for i, tran in enumerate(self.translated):
            # 检查message字段
            if "message" in tran:
                message = tran["message"]
                found_words = []

                # 检查每个禁用词
                for word in self.forbidden_words:
                    if word in message:
                        found_words.append(word)

                if found_words:
                    self.errors.append(
                        f"索引 {i} message字段中包含禁用词: {', '.join(found_words)}"
                    )
                    self.errors.append(
                        f"  原文message: {self.original[i].get('message', '无')}"
                    )
                    self.errors.append(f"  译文message: {message}")

                    # 高亮显示禁用词
                    highlighted = message
                    for word in found_words:
                        highlighted = highlighted.replace(word, f"【{word}】")
                    self.errors.append(f"  高亮显示: {highlighted}")
                    self.errors.append("")
                    success = False

            # 检查name字段
            if "name" in tran:
                name = tran["name"]
                found_words = []

                # 检查每个禁用词
                for word in self.forbidden_words:
                    if word in name:
                        found_words.append(word)

                if found_words:
                    self.errors.append(
                        f"索引 {i} name字段中包含禁用词: {', '.join(found_words)}"
                    )
                    self.errors.append(
                        f"  原文name: {self.original[i].get('name', '无')}"
                    )
                    self.errors.append(f"  译文name: {name}")

                    # 高亮显示禁用词
                    highlighted = name
                    for word in found_words:
                        highlighted = highlighted.replace(word, f"【{word}】")
                    self.errors.append(f"  高亮显示: {highlighted}")
                    self.errors.append("")
                    success = False

        return success

    def check_invisible_characters(self) -> bool:
        """检查译文中是否包含不可见字符"""
        success = True
        for i, tran in enumerate(self.translated):
            if "message" in tran:
                message = tran["message"]
                invisible_matches = self.invisible_pattern.findall(message)

                if invisible_matches:
                    # 统计每个不可见字符的出现次数
                    char_count = {}
                    for char in invisible_matches:
                        char_count[char] = char_count.get(char, 0) + 1

                    # 构建错误信息
                    char_details = []
                    for char, count in char_count.items():
                        char_name = self.invisible_char_names.get(
                            char, f"U+{ord(char):04X}(未知不可见字符)"
                        )
                        char_details.append(f"{char_name}: {count}次")

                    self.errors.append(
                        f"索引 {i} 译文中包含不可见字符:\n  "
                        + "\n  ".join(char_details)
                    )
                    self.errors.append(f"  译文: {repr(message)}")

                    # 高亮显示不可见字符位置
                    highlighted = message
                    for char in char_count.keys():
                        placeholder = f"【{self.invisible_char_names.get(char, f'U+{ord(char):04X}').split(
                            '(')[0]}】"
                        highlighted = highlighted.replace(char, placeholder)
                    self.errors.append(f"  高亮显示: {highlighted}")
                    self.errors.append("")
                    success = False

            # 同时也检查name字段
            if "name" in tran:
                name = tran["name"]
                invisible_matches = self.invisible_pattern.findall(name)

                if invisible_matches:
                    char_count = {}
                    for char in invisible_matches:
                        char_count[char] = char_count.get(char, 0) + 1

                    char_details = []
                    for char, count in char_count.items():
                        char_name = self.invisible_char_names.get(
                            char, f"U+{ord(char):04X}(未知不可见字符)"
                        )
                        char_details.append(f"{char_name}: {count}次")

                    self.errors.append(
                        f"索引 {i} name字段中包含不可见字符:\n  "
                        + "\n  ".join(char_details)
                    )
                    self.errors.append(f"  name: {repr(name)}")
                    self.errors.append("")
                    success = False

        return success

    def check_quote_consistency(self) -> bool:
        """检查开头和结尾的引号是否与原文一致"""
        success = True
        for i, (orig, tran) in enumerate(zip(self.original, self.translated)):
            if "message" not in orig or "message" not in tran:
                continue

            o = orig["message"].strip()
            t = tran["message"].strip()

            if not o or not t:
                continue

            # 检查开头引号
            if o[0] in "「『" and o[0] != t[0]:
                self.errors.append(
                    f"索引 {i} 开头引号不一致:\n 原文'{o}'\n 译文'{t if t else '无'}'\n"
                )
                success = False

            # 检查结尾引号
            if o[-1] in "」』" and o[-1] != t[-1]:
                self.errors.append(
                    f"索引 {i} 结尾引号不一致:\n 原文'{o}'\n 译文'{t if t else '无'}'\n"
                )
                success = False

            # 检查开头引号
            if t[0] in "「『" and o[0] != t[0]:
                self.errors.append(
                    f"索引 {i} 开头引号不一致:\n 原文'{o}'\n 译文'{t if t else '无'}'\n"
                )
                success = False

            # 检查结尾引号
            if t[-1] in "」』" and o[-1] != t[-1]:
                self.errors.append(
                    f"索引 {i} 结尾引号不一致:\n 原文'{o}'\n 译文'{t if t else '无'}'\n"
                )
                success = False

        return success

    def check_korean_characters(self) -> bool:
        """检查译文中是否包含韩文字符"""
        success = True
        for i, tran in enumerate(self.translated):
            if "message" in tran:
                message = tran["message"]
                korean_matches = self.korean_pattern.findall(message)

                if korean_matches:
                    # 去重并显示找到的韩文字符
                    unique_chars = list(set(korean_matches))
                    self.errors.append(f"索引 {i} 译文中包含韩文字符: {unique_chars}")
                    self.errors.append(f"  译文: {message}")

                    # 高亮显示韩文字符位置
                    highlighted = message
                    for char in unique_chars:
                        highlighted = highlighted.replace(char, f"【{char}】")
                    self.errors.append(f"  高亮显示: {highlighted}")
                    self.errors.append("")
                    success = False

        return success

    def check_japanese_characters(self) -> bool:
        """检查译文中是否包含日语假名字符"""
        success = True
        for i, tran in enumerate(self.translated):
            if "message" in tran:
                message = tran["message"]

                # 检查平假名
                hiragana_matches = self.hiragana_pattern.findall(message)
                # 检查片假名
                katakana_matches = self.katakana_pattern.findall(message)

                all_japanese_matches = hiragana_matches + katakana_matches

                if all_japanese_matches:
                    # 去重并分类显示找到的日语字符
                    unique_hiragana = list(set(hiragana_matches))
                    unique_katakana = list(set(katakana_matches))

                    error_msg = f"索引 {i} 译文中包含日语假名字符:"
                    if unique_hiragana:
                        error_msg += f" 平假名{unique_hiragana}"
                    if unique_katakana:
                        error_msg += f" 片假名{unique_katakana}"

                    self.errors.append(error_msg)
                    self.errors.append(f"  译文: {message}")

                    # 高亮显示日语字符位置
                    highlighted = message
                    for char in unique_hiragana + unique_katakana:
                        highlighted = highlighted.replace(char, f"【{char}】")
                    self.errors.append(f"  高亮显示: {highlighted}")
                    self.errors.append("")
                    success = False

        return success

    def check_duplicate_quotes(self) -> bool:
        """检查译文中是否有重复的「」和『』"""
        success = True
        for i, tran in enumerate(self.translated):
            if "message" in tran:
                message = tran["message"]

                # 检查重复的「
                if "「「" in message:
                    self.errors.append(f"索引 {i} 译文中包含重复的「「")
                    self.errors.append(f"  译文: {message}")

                    # 高亮显示重复的「
                    highlighted = message.replace("「「", "【「「】")
                    self.errors.append(f"  高亮显示: {highlighted}")
                    self.errors.append("")
                    success = False

                # 检查重复的」
                if "」」" in message:
                    self.errors.append(f"索引 {i} 译文中包含重复的」」")
                    self.errors.append(f"  译文: {message}")

                    # 高亮显示重复的」
                    highlighted = message.replace("」」", "【」」】")
                    self.errors.append(f"  高亮显示: {highlighted}")
                    self.errors.append("")
                    success = False

                # 检查重复的『
                if "『『" in message:
                    self.errors.append(f"索引 {i} 译文中包含重复的『『")
                    self.errors.append(f"  译文: {message}")

                    # 高亮显示重复的『
                    highlighted = message.replace("『『", "【『『】")
                    self.errors.append(f"  高亮显示: {highlighted}")
                    self.errors.append("")
                    success = False

                # 检查重复的』
                if "』』" in message:
                    self.errors.append(f"索引 {i} 译文中包含重复的』』")
                    self.errors.append(f"  译文: {message}")

                    # 高亮显示重复的』
                    highlighted = message.replace("』』", "【』』】")
                    self.errors.append(f"  高亮显示: {highlighted}")
                    self.errors.append("")
                    success = False

        return success

    def check_length_discrepancy(self) -> bool:
        """检查译文和原文的字符数量差是否过大"""
        success = True
        threshold_ratio = 2.0  # 译文长度不能超过原文长度的2倍
        min_ratio = 0.3  # 译文长度不能少于原文长度的30%

        for i, (orig, tran) in enumerate(zip(self.original, self.translated)):
            # 只检查message字段
            if "message" in orig and "message" in tran:
                orig_message = orig["message"]
                tran_message = tran["message"]

                orig_len = len(orig_message)
                tran_len = len(tran_message)

                # 避免除零错误
                if orig_len > 0:
                    length_ratio = tran_len / orig_len

                    if length_ratio > threshold_ratio:
                        self.errors.append(
                            f"索引 {i} 译文长度过长: "
                            f"原文长度 {orig_len}，译文长度 {tran_len}，比例 {length_ratio:.2f} (超过阈值 {threshold_ratio})"
                        )
                        self.errors.append(f"  原文: {orig_message}")
                        self.errors.append(f"  译文: {tran_message}")
                        self.errors.append("")
                        success = False

                    elif length_ratio < min_ratio:
                        self.errors.append(
                            f"索引 {i} 译文长度过短: "
                            f"原文长度 {orig_len}，译文长度 {tran_len}，比例 {length_ratio:.2f} (低于阈值 {min_ratio})"
                        )
                        self.errors.append(f"  原文: {orig_message}")
                        self.errors.append(f"  译文: {tran_message}")
                        self.errors.append("")
                        success = False

        return success

    def extract_special_chars(self, text: str) -> List[str]:
        """从文本中提取特殊字符序列"""
        result = []
        i = 0
        while i < len(text):
            if text[i] == "@" and i + 1 < len(text):
                char_pair = text[i: i + 2]
                if char_pair in self.special_chars:
                    result.append(char_pair)
                    i += 2  # 跳过两个字符
                    continue
            i += 1
        return result

    def check_special_characters(self) -> bool:
        """检查特殊字的顺序和数量是否一致"""
        success = True

        for i, (orig, tran) in enumerate(zip(self.original, self.translated)):
            # 检查message字段
            if "message" in orig and "message" in tran:
                orig_chars = self.extract_special_chars(orig["message"])
                tran_chars = self.extract_special_chars(tran["message"])

                if orig_chars != tran_chars:
                    self.errors.append(
                        f"索引 {i} message字段特殊字符不匹配: "
                        f"原文有 {len(orig_chars)} 个 [{', '.join(orig_chars)}]，"
                        f"译文有 {len(tran_chars)} 个 [{', '.join(tran_chars)}]"
                    )
                    self.print_item_error(i, orig, tran)
                    success = False

            # 检查name字段（如果存在）
            if "name" in orig and "name" in tran:
                orig_name_chars = self.extract_special_chars(orig["name"])
                tran_name_chars = self.extract_special_chars(tran["name"])

                if orig_name_chars != tran_name_chars:
                    self.errors.append(
                        f"索引 {i} name字段特殊字符不匹配: "
                        f"原文有 {len(orig_name_chars)} 个 [{', '.join(orig_name_chars)}]，"
                        f"译文有 {len(tran_name_chars)} 个 [{', '.join(tran_name_chars)}]"
                    )
                    self.print_item_error(i, orig, tran)
                    success = False

            # 检查字段存在性是否一致
            if ("name" in orig) != ("name" in tran):
                self.errors.append(
                    f"索引 {i} name字段存在性不匹配: "
                    f"原文{'有' if 'name' in orig else '无'}name字段，"
                    f"译文{'有' if 'name' in tran else '无'}name字段"
                )
                self.print_item_error(i, orig, tran)
                success = False

        return success

    def print_item_error(self, index: int, original_item: Dict, translated_item: Dict):
        """打印出错项的详细信息"""
        self.errors.append(f"  原文: {original_item}")
        self.errors.append(f"  译文: {translated_item}")
        self.errors.append("")

    def run_checks(self) -> bool:
        """运行所有检查"""
        all_passed = True

        for check in self.checks:
            try:
                if not check():
                    all_passed = False
            except Exception as e:
                self.errors.append(f"检查 {check.__name__} 执行时出错: {str(e)}")
                all_passed = False

        return all_passed

    def print_errors(self):
        """打印所有错误信息"""
        if self.errors:
            print("检查发现以下错误:")
            for error in self.errors:
                print(error)
        else:
            print("所有检查通过!")


def load_json_file(file_path: str) -> List[Dict]:
    """加载JSON文件"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"加载文件 {file_path} 时出错: {str(e)}")
        sys.exit(1)


def main(original_file: str, translated_file: str):
    # 加载JSON文件
    original_json = load_json_file(original_file)
    translated_json = load_json_file(translated_file)

    # 创建检查器并运行检查
    checker = JSONChecker(original_json, translated_json)
    success = checker.run_checks()

    # 输出结果
    checker.print_errors()

    # 根据检查结果返回适当的退出码
    return 0 if success else 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("用法: python json_checker.py <原文json文件> <译文json文件>")
        sys.exit(1)

    original_file = sys.argv[1]
    translated_file = sys.argv[2]

    sys.exit(main(original_file, translated_file))
