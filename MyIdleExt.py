"""My Idle Extension"""
import re
import os
import sys
import string
import tkinter
import tkinter.messagebox
import tempfile
from idlelib.configHandler import idleConf

try:
    import autopep8
except (ImportError, ValueError):
    autopep8 = None

config_extension_def = """
[MyIdleExt]
enable=1
enable_editor=1
enable_shell=0

[MyIdleExt_cfgBindings]
format-pep8=<Control-l>

"""


def split_index(string):
    return [int(value) for value in string.split('.')]


def join_index(line, char):
    return '{}.{}'.format(line, char)


def every_two(iterable):
    iterator = iter(iterable)
    try:
        while True:
            a = next(iterator)
            b = next(iterator)
            yield a, b

    except StopIteration:
        return


def include(index_range, target):
    start, end = index_range
    return split_index(start) <= split_index(target) < split_index(end)


class TextIndex:
    def __init__(self, value):
        if isinstance(value, str):
            self.row, self.column = split_index(value)
        elif isinstance(value, (tuple, list)):
            self.row, self.column = value
        elif isinstance(value, TextIndex):
            self.row = value.row
            self.column = value.column
        else:
            self.row, self.column = split_index(value.string)

    def __repr__(self):
        return join_index(self.row, self.column)

    def __str__(self):
        return join_index(self.row, self.column)

    def __add__(self, other):
        if isinstance(other, int):
            other = '+{}c'.format(other)
        return join_index(self.row, self.column) + other

    def __sub__(self, other):
        if isinstance(other, int):
            other = '-{}c'.format(other)
            return join_index(self.row, self.column) + other
        else:
            return NotImplemented

    def __getitem__(self, item):
        if item == 0:
            return self.row
        elif item == 1:
            return self.column
        else:
            raise IndexError

    def __getattr__(self, item):
        if not item.startswith('__'):
            return getattr(repr(self), item)
        else:
            raise AttributeError(item)

    def __lt__(self, other):
        # print('{} < {}'.format(self, other))
        if isinstance(other, TextIndex):
            return (self.row, self.column) < (other.row, other.column)
        elif isinstance(other, (str, tuple, list)) or hasattr(other, 'string'):
            return self < TextIndex(other)

    def __eq__(self, other):
        # print('{} == {}'.format(self, other))
        if isinstance(other, TextIndex):
            return (self.row, self.column) == (other.row, other.column)
        elif isinstance(other, (str, tuple, list)) or hasattr(other, 'string'):
            return self == TextIndex(other)

    def __gt__(self, other):
        # print('{} > {}'.format(self, other))
        if isinstance(other, TextIndex):
            return (self.row, self.column) > (other.row, other.column)
        elif isinstance(other, (str, tuple, list)) or hasattr(other, 'string'):
            return self > TextIndex(other)

    def __le__(self, other):
        return self < other or self == other

    def __ge__(self, other):
        return self > other or self == other


class MyIdleExt:
    # any_bracket_pattern = re.compile(r"(\(|\{|\[|\)|\}|\])")

    close_brackets = {
        '(': ')',
        '[': ']',
        '{': '}',
        "'": "'",
        '"': '"'
    }

    open_brackets = {value: key for key, value in close_brackets.items()}

    quotes = ['"', "'"]

    identifier_chars = string.ascii_letters + string.digits + '_'

    menudefs = [
        ('format', [
            ("Format PEP8", "<<format-pep8>>"),
        ])
    ]

    def __init__(self, editwin):
        self.window = editwin
        self.text = editwin.text
        self.bell = self.text.bell

        self.text.bind('<Key-(>', self.expand_brackets_or_quotes)
        self.text.bind('<Key-[>', self.expand_brackets_or_quotes)
        self.text.bind('<Key-{>', self.expand_brackets_or_quotes)
        self.text.bind("<Key-'>", self.expand_brackets_or_quotes)
        self.text.bind('<Key-">', self.expand_brackets_or_quotes)

        self.text.bind('<Key-)>', self.handle_close_bracket)
        self.text.bind('<Key-]>', self.handle_close_bracket)
        self.text.bind('<Key-}>', self.handle_close_bracket)

        self.text.bind('<BackSpace>', self.handle_backspace)

        self.text.bind('<<format-pep8>>', self.format_pep8)
        self.text.bind(idleConf.GetOption('extensions', 'MyIdleExt_cfgBindings', 'format-pep8'), self.format_pep8)

    def expand_brackets_or_quotes(self, event):
        open_bracket = event.char
        close_bracket = self.close_brackets[event.char]
        try:
            # 选中了一些文本，现在用括号（或引号）将它们括起来
            self.wrap_selection_with(open_bracket, close_bracket)
            return 'break'

        except (tkinter.TclError, AssertionError):
            pass
        # 似乎当前并没有选中文本
        # 如果有需要，补全另一个括号
        cursor = self.get_cursor()
        next_char = self.text.get('insert')

        if open_bracket in self.quotes:
            quote = open_bracket
            if self.position_in_tags(cursor, ('COMMENT',)):
                return

            # 字符串中输入引号，需要额外考虑
            in_string = self.position_in_tags(cursor, ('STRING',))
            if in_string:
                start, end = in_string

                return self.handle_close_quote(quote, next_char, cursor, start, end)

            else:
                two_chars_before = self.text.get(cursor - 2, cursor)

                if len(two_chars_before) >= 2 and two_chars_before[0] == two_chars_before[1] == quote:  # 开启三引号字符串
                    self.text.insert(cursor, quote * 4)
                    self.text.mark_set('insert', cursor + 1)
                    return 'break'

        elif self.position_in_tags(cursor):  # 字符串或注释中，不补全括号
            return

        if next_char is '' or next_char not in self.identifier_chars:
            self.text.insert(cursor, open_bracket + close_bracket)
            self.text.mark_set('insert', cursor + 1)
            return 'break'

    def handle_close_bracket(self, event):
        close_bracket = event.char
        open_bracket = self.open_brackets[close_bracket]

        try:
            self.wrap_selection_with(open_bracket, close_bracket)

        except (AssertionError, tkinter.TclError):
            pass

        cursor = self.get_cursor()

        if self.position_in_tags(cursor):
            return

        next_char = self.text.get(cursor)
        if next_char == close_bracket:
            self.text.mark_set('insert', cursor + 1)
            return 'break'

    def handle_close_quote(self, quote, next_char, cursor, start, end):
        quote_type = self.parse_quote_type(start)

        if quote_type is None:
            return

        if quote == quote_type and len(quote_type) == 1:
            two_chars_before = self.text.get(cursor - 2, cursor)
            if len(two_chars_before) >= 2 and two_chars_before[1] == '\\' and two_chars_before[0] != '\\':
                return  # 该引号已被转义

            if quote == next_char:
                self.text.mark_set('insert', cursor + 1)  # 字符串已闭合，移动光标即可
                return 'break'

            else:
                return  # 此引号用于闭合字符串，不做处理

        elif quote == quote_type[0] and len(quote_type) == 3:
            chars_around = self.text.get(cursor - 2, cursor + 3)
            if quote_type in chars_around:
                self.text.mark_set('insert', cursor + 1)  # 字符串已闭合
                return 'break'

            # other_two_quote = self.text.get(cursor + '-2c', cursor)
            # two_chars_before = self.text.get(cursor + '-4c', cursor + '-2c')
            #
            # if other_two_quote == close_bracket * 2:
            #     if two_chars_before[1] == '\\' and two_chars_before[0] != '\\':
            #         return  # 转义
            #     else:
            #         return  # 闭合该字符串
            #
            # else:
            #     return
            return  # 以上每种情况都不做处理

    def handle_backspace(self, event):
        cursor = self.get_cursor()
        deleting_char = self.text.get(cursor - 1)
        if deleting_char in '{[(':
            return self.delete_bracket(deleting_char, cursor)

        elif deleting_char in ('"', "'"):
            return self.delete_quote(deleting_char, cursor)

        elif deleting_char == ' ':
            return self.delete_indent(deleting_char, cursor)

    def delete_bracket(self, bracket, cursor):
        next_char = self.text.get(cursor)
        if next_char == self.close_brackets[bracket]:
            self.text.delete(cursor - 1, cursor + 1)
            return 'break'
        return None

    def delete_quote(self, quote, cursor):
        in_string = self.position_in_tags(cursor, tags=('STRING',))
        if not in_string:
            return
        start, end = in_string
        quote_type = self.parse_quote_type(start)
        if self.text.get(start, end) == quote_type * 2:
            self.text.delete(start, end)
            return 'break'

    def delete_indent(self, space, cursor):
        this_line = self.text.get(join_index(cursor.row, 0), cursor)
        if this_line.isspace():
            if len(this_line) % 4 == 0:
                self.text.delete(cursor - 4, cursor)
                return 'break'
            else:
                self.text.delete(cursor - len(this_line) % 4, cursor)
                return 'break'

    def position_in_tags(self, cursor, tags=('STRING', 'COMMENT')):
        # print('position_in_tags({!r}, {!r})'.format(cursor, tags))
        exclude_ranges = sum((self.text.tag_ranges(tag) for tag in tags), ())
        for start, stop in every_two(exclude_ranges):
            start_index = TextIndex(start)
            stop_index = TextIndex(stop)
            # print('values', start_index, cursor, stop_index)
            if start_index <= cursor < stop_index:
                return start_index, stop_index
            # print('Now cursor is', cursor)
        else:
            return None

    def wrap_selection_with(self, left, right):
        start = self.text.index('sel.first')
        end = self.text.index('sel.last')
        assert start != '' and end != ''
        self.text.insert(end, right)
        self.text.insert(start, left)
        self.text.tag_delete('sel')
        self.text.tag_add('sel', start, end + '+2c')
        self.text.update()

    def get_cursor(self):
        return TextIndex(self.text.index('insert'))

    def parse_quote_type(self, string_start_pos):
        quote_start = self.text.get(string_start_pos, string_start_pos + 6).strip(string.ascii_letters)  # 去除字符串前缀
        if quote_start[:3] == "'''":
            return "'''"
        elif quote_start[:3] == '"""':
            return '"""'
        elif quote_start[0] == "'":
            return "'"
        elif quote_start[0] == '"':
            return '"'
        else:
            return None  # 未知起始引号类型

    def format_pep8(self, event):
        global autopep8
        if autopep8 is None:
            try:
                import autopep8
            except (ImportError, ValueError):
                tkinter.Tk().withdraw()
                tkinter.messagebox.showerror('autopep8 Is Not Installed',
                                             'Cannot pretty-format your code, because autopep8 is not installed. '
                                             'Install it by run command "python -m pip install autopep8", '
                                             'and then restart IDLE.')
                return
        try:
            raw_code = self.text.get('1.0', 'end')
            with tempfile.TemporaryDirectory() as directory:
                filename = os.path.join(directory, 'temp.py')
                with open(filename, 'w', encoding='utf-8') as fp:
                    fp.write(raw_code)
                autopep8.main(['autopep8.py', filename, '--in-place', '--aggressive', '--aggressive'])
                with open(filename, 'r', encoding='utf-8') as fp:
                    formatted_code = fp.read()

            self.text.delete('1.0', 'end')
            self.text.insert('1.0', formatted_code)
        except Exception:
            import traceback
            traceback.print_exc()

# class BracketsMatcher:
#     def __init__(self):
#         self.before = []
#         self.after = []
#         self.before_quote = ''
#         self.after_quote = ''
#
#     def parse_before(self, text):
#
#         for i, char in zip(range(len(text) - 1, -1, -1), reversed(text)):
#             if char in ('"', "'"):
#                 if self.before_quote == '':
#                     if text[i + 1:i + 3] == char * 2:
#                         self.before_quote = char * 3
#                     else:
#                         self.before_quote = char
#
#                 elif char in self.before_quote:
#                     two_chars_before = text[i - 2:i]
#                     if two_chars_before[1] == '\\' and two_chars_before[0] != '\\':
#                         continue
#                     elif char == self.before_quote:
#                         self.before_quote = ''
#                     elif text[i + 1:i + 3] == char * 2:
#                         self.before_quote = ''
#
#             elif char in (':', ';')
