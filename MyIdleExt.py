"""
MyIdleExt -- My Idle Extension
------------------------------
This is a idle extension which provides code completion,
brackets/quotes completion and more features.
This file should be loaded by idlelib.
In this way, it will provide the features mentioned above.
Otherwise, if you run this file as `__main__` (Run directly),
you can do some operations such as install and uninstall.
"""
import logging
import traceback
import io
import types
import builtins
import keyword
from code import InteractiveInterpreter
import glob
import inspect
import ast
import tempfile
import tkinter.ttk
import tkinter.messagebox
import tkinter
import random
import string
import re
import os
import sys

version = _version_ = '0.3.0'

config_extension_def = """
[MyIdleExt]
enable=True
enable_editor=True
enable_shell=False
color_keyword_fg = #ff7700
color_builtin_fg = #900090
color_idle_fg = #ff00ff
color_abc_fg = #b0b0b0
color_module-name_fg = #d6d600
color_package-name_fg = #d6d600
color_module_fg = #d6d600
color_function_fg = #c8c800
color_parameter_fg = #000000
color_variable_fg = #000000

[MyIdleExt_cfgBindings]
format-pep8=<Control-l>

"""


def on_run_as_main():
    import shutil
    import traceback
    import argparse
    import configparser
    try:
        from idlelib.config import idleConf
    except ImportError:
        from idlelib.configHandler import idleConf

    def find_idlelib():
        for path in sys.path:
            try:
                for directory in os.listdir(path):
                    if (directory == 'idlelib' and
                            os.path.isdir(os.path.join(path, directory))):
                        config_extension_filename = os.path.join(
                            path, directory, 'config-extensions.def')
                        if os.path.isfile(config_extension_filename):
                            return os.path.join(path, 'idlelib')
            except OSError:
                pass
        print('`idlelib` not found. Try to specified the path of it. ')
        sys.exit()

    arg_parser = argparse.ArgumentParser('MyIdleExt', description=__doc__)
    subparsers_group = arg_parser.add_subparsers(
        title='Commands', dest='command', metavar='<command>')

    command_install = subparsers_group.add_parser(
        'install',
        help='Install MyIdleExt for your idle. '
        'You might need to restart idle to apply. '
    )
    command_install.add_argument(
        '--path',
        help='The path of idlelib to install MyIdleExt. '
        'If is not specified, program will search it in `sys.path`. ',
        default=''
    )
    command_install.add_argument('--sure', action='store_const',
                                 const=True, default=False,
                                 help='If it is already installed, '
                                 'do not ask if the user want to overwrite. ')
    which_config = command_install.add_mutually_exclusive_group()
    which_config.add_argument('--user', action='store_const', const=['user'],
                              dest='which_config',
                              help='Enable for the current user. ',
                              default=['user'])
    which_config.add_argument('--default', action='store_const',
                              const=['default'], dest='which_config',
                              help='Enable for the default idle configure. ',
                              default=['user'])
    which_config.add_argument(
        '--both', action='store_const',
        const=['user', 'default'], default=['user'],
        dest='which_config',
        help='Enable for both the current user and the default. '
    )

    command_uninstall = subparsers_group.add_parser(
        'uninstall', help='Uninstall MyIdleExt for your idle')
    command_uninstall.add_argument(
        '--path',
        help='The path of idlelib to uninstall MyIdleExt. '
        'If is not specified, program will search it in `sys.path`. ',
        default=''
    )
    command_uninstall.add_argument(
        '--sure', action='store_const',
        const=True, default=False,
        help='Do not ask if the user really want to uninstall. '
    )
    which_config = command_uninstall.add_mutually_exclusive_group()
    which_config.add_argument('--user', action='store_const',
                              const=['user'], dest='which_config',
                              help='Disable for the current user. ',
                              default=['user'])
    which_config.add_argument('--default', action='store_const',
                              const=['default'], dest='which_config',
                              help='Disable for the default idle configure. ',
                              default=['user'])
    which_config.add_argument('--both', action='store_const',
                              const=['user', 'default'], default=['user'],
                              dest='which_config',
                              help='Disable for both the current user'
                                   ' and the default. ')

    subparsers_group.add_parser('version',
                                help='Show the version of MyIdleExt. ')

    def is_installed(idle_path):
        return os.path.isfile(os.path.join(idle_path, 'MyIdleExt.py'))

    def ask_yes_no(question):
        while True:
            answer = input(question + ' (y/n)> ')
            if answer == 'y':
                return True
            elif answer == 'n':
                return False
            else:
                print("Please input 'y' or 'n'. Try again. ")

    def get_idle_ext_config_path(which):
        if which == 'default':
            return os.path.join(find_idlelib(), 'config-extensions.def')
        elif which == 'user':
            return os.path.join(idleConf.GetUserCfgDir(),
                                'config-extensions.def')

    def install(this, args):
        if args.path == '':
            args.path = find_idlelib()
        if is_installed(args.path) and not args.sure:
            if not ask_yes_no('MyIdleExt looks already installed in "{}". '
                              'Are you sure to overwrite?'.format(args.path)):
                print('Operation canceled. ')
                return
        try:
            shutil.copy(this, os.path.join(args.path, 'MyIdleExt.py'))
        except shutil.SameFileError:
            pass
        default_config = configparser.ConfigParser()
        default_config.read_string(config_extension_def)

        for which_config in args.which_config:
            config_path = get_idle_ext_config_path(which_config)
            idle_config = configparser.ConfigParser()
            idle_config.read(config_path)
            for section in default_config.sections():
                if not idle_config.has_section(section):
                    idle_config.add_section(section)
                for key, value in default_config.items(section):
                    idle_config.set(section, key, value)

            with open(config_path, 'w') as fp:
                idle_config.write(fp)

        print('MyIdleExt installed successfully. ')

    def uninstall(this, args):
        if args.path == '':
            args.path = find_idlelib()
        if not is_installed(args.path):
            print('MyIdleExt is not installed. ')
            return
        if not args.sure:
            if not ask_yes_no('Are you sure to uninstall MyIdleExt in "{}"?'
                              .format(args.path)):
                print('Operation canceled. ')
        os.remove(os.path.join(args.path, 'MyIdleExt.py'))
        default_config = configparser.ConfigParser()
        default_config.read_string(config_extension_def)

        for which_config in args.which_config:
            config_path = get_idle_ext_config_path(which_config)
            idle_config = configparser.ConfigParser()
            idle_config.read(config_path)
            for section in default_config.sections():
                if idle_config.has_section(section):
                    idle_config.remove_section(section)

            with open(config_path, 'w') as fp:
                idle_config.write(fp)

        print('MyIdleExt uninstalled successfully. ')

    def version(this, args):
        print(_version_)

    args = arg_parser.parse_args()
    this = sys.argv[0]

    if args.command is None:
        print("You did not give any arguments in the command line. ")
        print('But do not be worried -- you can input here. ')
        print('Type `all` for all commands, `help` for help, '
              '`<command> -h` for help with the specifiesd command, '
              'or `quit` to quit ')
        pattern = re.compile(r'"[^"]*"|[^ "]*')

        while True:
            command = input('command> ')
            if command.strip() == 'all':
                print(*subparsers_group.choices, sep='\n')
                continue
            if command.strip() == 'quit':
                sys.exit()
            if command.strip() == 'help':
                arg_parser.print_help()
            else:
                try:
                    args = arg_parser.parse_args([
                        arg.strip('"')
                        for arg in pattern.findall(command)
                        if arg.strip()
                    ])
                    if args.command is None:
                        print('Please input a command')
                    else:
                        try:
                            locals()[args.command](this, args)
                        except Exception:
                            traceback.print_exc()
                except SystemExit:
                    pass

    else:
        locals()[args.command](this, args)


if __name__ == '__main__':
    on_run_as_main()
    sys.exit()


try:
    from idlelib.config import idleConf
except ImportError:
    from idlelib.configHandler import idleConf

try:
    from idlelib.editor import EditorWindow
except ImportError:
    from idlelib.EditorWindow import EditorWindow

has_idle_autocomplete = True
try:
    from idlelib.autocomplete import (AutoComplete, HyperParser,
                                      ATTRS as COMPLETE_ATTRIBUTES)
    from idlelib import autocomplete
except ImportError:
    try:
        from idlelib.AutoComplete import (AutoComplete,
                                          HyperParser,
                                          COMPLETE_ATTRIBUTES)
        from idlelib import AutoComplete as autocomplete
    except ImportError:
        has_idle_autocomplete = False

try:
    import autopep8
except (ImportError, ValueError):
    autopep8 = None


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


def is_escape(string):
    if len(string) == 0:
        return False
    elif len(string) == 1:
        return string == '\\'
    else:
        if string[-1] != '\\':
            return False
        backslash_count = 0
        for char in reversed(string[:-1]):
            if char == '\\':
                backslash_count += 1
            else:
                break
        return backslash_count % 2 == 0


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

        if isinstance(other, TextIndex):
            return (self.row, self.column) < (other.row, other.column)
        elif isinstance(other, (str, tuple, list)) or hasattr(other, 'string'):
            return self < TextIndex(other)

    def __eq__(self, other):

        if isinstance(other, TextIndex):
            return (self.row, self.column) == (other.row, other.column)
        elif isinstance(other, (str, tuple, list)) or hasattr(other, 'string'):
            return self == TextIndex(other)

    def __gt__(self, other):

        if isinstance(other, TextIndex):
            return (self.row, self.column) > (other.row, other.column)
        elif isinstance(other, (str, tuple, list)) or hasattr(other, 'string'):
            return self > TextIndex(other)

    def __le__(self, other):
        return self < other or self == other

    def __ge__(self, other):
        return self > other or self == other

    def __iter__(self):
        return iter((self.row, self.column))

    @property
    def line_start(self):
        return join_index(self.row, 0)

    @property
    def line_end(self):
        return join_index(self.row, 'end')


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

    def __init__(self, editwin: EditorWindow):
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

        self.text.bind('<<format-pep8>>', self.format_pep8)
        self.text.bind(idleConf.GetOption(
            'extensions', 'MyIdleExt_cfgBindings', 'format-pep8'),
            self.format_pep8)

        self.completion = CodeCompletionWindow(self, self.window.top)

        self.text.bind('<Tab>', self.handle_tab, add=True)
        self.text.bind('<Key>', self.handle_key, add=True)

        if has_idle_autocomplete:
            class FakeObject:
                """“假”对象，允许任何方法调用，不报错，不执行任何操作"""

                def __init__(self, *args, **kwargs):
                    pass

                def __getattr__(self, item):
                    return self

                def __call__(self, *args, **kwargs):
                    return self

                def __getitem__(self, item):
                    return self

            # 禁止 idle.autocomplete 弹出窗口
            autocomplete.AutoComplete._make_autocomplete_window = FakeObject()

            self.idle_autocomplete = AutoComplete(editwin)
        else:
            self.idle_autocomplete = None

        self.shell = InteractiveInterpreter()

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

                return self.handle_close_quote(quote, next_char,
                                               cursor, start, end)

            else:
                two_chars_before = self.text.get(cursor - 2, cursor)

                # 开启三引号字符串
                if (len(two_chars_before) >= 2 and
                        two_chars_before[0] == two_chars_before[1] == quote):
                    self.text.insert(cursor, quote * 4)
                    self.text.mark_set('insert', cursor + 1)
                    return 'break'

        elif self.position_in_tags(cursor):  # 字符串或注释中，不补全括号
            return

        if next_char == '' or next_char not in self.identifier_chars:
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
            chars_before = self.text.get(cursor.line_start, cursor)
            if is_escape(chars_before):
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
            #     if (two_chars_before[1] == '\\' and
            #             two_chars_before[0] != '\\'):
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

        exclude_ranges = sum((self.text.tag_ranges(tag) for tag in tags), ())
        for start, stop in every_two(exclude_ranges):
            start_index = TextIndex(start)
            stop_index = TextIndex(stop)

            if start_index <= cursor < stop_index:
                return start_index, stop_index

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
        # 去除字符串前缀
        quote_start = (self.text.get(string_start_pos, string_start_pos + 6)
                       .strip(string.ascii_letters))
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
                tkinter.messagebox.showerror(
                    'autopep8 Is Not Installed',
                    'Cannot pretty-format your code, '
                    'because autopep8 is not installed. '
                    'Install it by run command '
                    '"python -m pip install autopep8", '
                    'and then restart IDLE.')
                return
        try:
            raw_code = self.text.get('1.0', 'end')
            with tempfile.TemporaryDirectory() as directory:
                filename = os.path.join(directory, 'temp.py')
                with open(filename, 'w', encoding='utf-8') as fp:
                    fp.write(raw_code)
                autopep8.main(['autopep8.py', filename,
                               '--in-place', '--aggressive', '--aggressive'])
                with open(filename, 'r', encoding='utf-8') as fp:
                    formatted_code = fp.read()

            self.text.delete('1.0', 'end')
            self.text.insert('1.0', formatted_code)
        except Exception:
            import traceback
            traceback.print_exc()

    def handle_key(self, event):

        if event.char == '':
            return

        if event.char == '\b':
            return self.handle_backspace(event)

        if event.char == '\r':
            return self.window.newline_and_indent_event(event)

        if event.char in string.ascii_letters or event.char == '.':
            cursor = self.get_cursor()
            if self.position_in_tags(cursor):
                return

            self.text.after_idle(self.open_completion)
            # if event.char == '.':  # 阻止idle原本的自动提示弹出
            #     self.text.insert('insert', '.')
            #     return 'break'

    def handle_tab(self, event):
        cursor = self.get_cursor()
        text_before = self.text.get(cursor.line_start, cursor).strip()
        if text_before != '' and (self.completion.get_word() != ''
                                  or text_before[-1] == '.'):
            self.text.after_idle(self.open_completion)
            return 'break'

    @staticmethod
    def get_expr(code):
        match = re.search(r'(?:\w|\.|\d)+', code[::-1])
        if match is None:
            return ''
        else:
            return match.group()[::-1]

    def get_suggests(self, expr=None):
        code = self.text.get('1.0', 'end')
        parser = CodeParser(code, self)
        parser.prepare()
        return parser.get_suggests(expr)

    def open_completion(self, event=None):
        try:
            if self.completion.is_active:
                return
            self.completion.suggests = self.get_suggests(
                self.get_expr(self.text.get('insert linestart', 'insert')))
            self.completion.activate()
            return 'break'
        except Exception:
            traceback.print_exc()


def ast_eq(left, right):
    if not isinstance(left, ast.AST) or not isinstance(right, ast.AST):
        return left == right
    if type(left) != type(right):
        return False
    return all(ast_eq(getattr(left, field), getattr(right, field))
               for field in left._fields)


class CodeParser:
    def __init__(self, code, master: MyIdleExt):
        self.code = code
        self.imports = []
        self.fromimports = []

        self.master = master
        # 解析语法时如遇到SyntaxError，尝试在出错位置加入以下字符串，以修复用户在点号后尚未输入标识符的语法错误
        self.fix_empty_identifier = '_fix_empty_identifier_{:04d}_'.format(
            random.randint(0, 9999))

        self.code_lines = code.splitlines(True)
        self.line_starts = [0]
        for i, line in enumerate(self.code_lines):
            self.line_starts.append(self.line_starts[i] + len(line))
        self.tree = self.parse_as_more_as_possible()

    def parse_as_more_as_possible(self, end_lineno=None):

        code_lines = self.code.splitlines(True)
        end_lineno = len(code_lines) if end_lineno is None else end_lineno
        tried_fix = False
        while True:
            try:

                tree = ast.parse(''.join(code_lines[:end_lineno]))
            except SyntaxError as syntax_error:
                if ((not tried_fix) and
                        syntax_error.msg.strip().lower() == 'invalid syntax'):

                    try:
                        # 尝试修正点号后面没有标识符的错误
                        error_line = code_lines[syntax_error.lineno - 1]
                        start = 0

                        fixed_line = io.StringIO()
                        index = 0
                        while index < len(error_line):
                            index = error_line.find('.', start)
                            if index == -1:
                                break
                            if (error_line[index + 1]
                                    not in self.master.identifier_chars):
                                fixed_line.write(error_line[start:index + 1])
                                fixed_line.write(self.fix_empty_identifier)
                            start = index + 1
                        fixed_line.write(error_line[start:])
                        code_lines[syntax_error.lineno -
                                   1] = fixed_line.getvalue()

                        tried_fix = True
                    except Exception:
                        traceback.print_exc()
                    else:
                        continue

                end_lineno = syntax_error.lineno - 1
                tried_fix = False
            else:
                break

        return tree

    def prepare(self):
        parser = self

        class Visitor(ast.NodeVisitor):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)

            def visit_Import(self, node):
                parser.imports.append(node)

            def visit_ImportFrom(self, node):
                parser.fromimports.append(node)

        Visitor().visit(self.tree)

    # def parse_expr(self, expr_string, start_lineno=1, start_offset=0):
    #     brackets = {'(': ')', '[': ']', '{': '}'}
    #     lineno = start_lineno
    #     col_offset = start_offset
    #     node = ast.Expr(lineno=lineno, col_offset=col_offset)
    #     index = 0
    #     string_quote = None
    #     comment = False
    #
    #     string_reg = re.compile(r"""(?P<prefix>[bru])?(?P<quote>'''|"""
    #                             r'''"""|'|").*(?<!(?<!\\)\\)(\\{2})*(?P=quote)''')
    #     while index < len(expr_string):
    #         cur_char = expr_string[index]
    #
    #         if cur_char == '#':
    #             comment = True
    #             index = str.find('\n', index) + 1
    #             lineno += 1
    #             col_offset = 0
    #
    #         string_match = string_reg.match(expr_string, index)
    #         if string_match:
    #             matched_str = string_match.group()
    #             index += len(matched_str)
    #             if '\n' not in matched_str:
    #                 col_offset += len(matched_str)
    #             else:
    #                 lineno += matched_str.count('\n')
    #                 col_offset = (len(matched_str)
    #                               - matched_str.rfind('\n') - 1)
    #
    #         if cur_char == '\n':
    #             lineno += 1
    #             col_offset = 0
    #         else:
    #             col_offset += 1

    # def get_node_path_and_end(self, node):
    #     path = []
    #     current_node = node
    #     end_pos = node.lineno, node.col_offset
    #     changed = True
    #     while changed:
    #         changed = False
    #         next_node = None
    #         path.append(current_node)
    #         for field, value in ast.iter_fields(current_node):
    #             if isinstance(value, list):
    #                 for item in reversed(value):
    #                     if isinstance(item, ast.AST):
    #                         try:
    #                             if (item.lineno, item.col_offset) > end_pos:
    #                                 end_pos = item.lineno, item.col_offset
    #                                 next_node = item
    #                                 changed = True
    #                                 break
    #                         except AttributeError:
    #                             pass
    #             elif isinstance(value, ast.AST):
    #                 try:
    #                     if (value.lineno, value.col_offset) > end_pos:
    #                         end_pos = value.lineno, value.col_offset
    #                         next_node = item
    #                         changed = True
    #                 except AttributeError:
    #                     pass
    #         if next_node is not None:
    #             current_node = next_node
    #         else:
    #             break
    #     end_lineno, end_col_offset = end_pos
    #     start_index = self.line_starts[node.lineno - 1] + node.col_offset
    #     end_index = self.line_starts[end_lineno - 1] + end_col_offset
    #     for end_index in range(end_index, len(self.code)):
    #         ast.parse(self.code[start_index:end_lineno])

    def handle_import(self, name):
        try:
            shell = self.master.shell
            shell.runcode('import ' + name)
            shell.runcode('_result_ = ' + name)
            return shell.locals['_result_']
        except Exception:
            return None

    def handle_fromimport(self, module, name):
        try:
            shell = self.master.shell
            shell.runcode('from ' + module + ' import ' + name)
            return shell.locals[name]
        except Exception:
            return None

    def parse_node(self, node, node_path):

        logging.debug('parse_node({}, {})'.format(
            ast.dump(node), [ast.dump(node) for node in node_path]))

        if isinstance(node, ast.Name):
            return self.find_name(node.id, node_path)

        elif isinstance(node, ast.Call):
            kind, func = self.parse_node(node.func, node_path)
            if kind == 'instance':
                if isinstance(func, type):
                    return 'instance', func
                result = 'instance', inspect.signature(func).return_annotation
                if result == inspect._emtpy:
                    return 'instance', None
                return 'instance', result
            elif kind == 'class':
                return 'class', func
            elif kind == 'func':
                result = None
                parser = self

                class Visitor(ast.NodeVisitor):
                    def visit_Return(self, node):
                        nonlocal result
                        if node.value is not None:
                            if isinstance(node.value, ast.Constant):
                                if node.value.value is not None:
                                    result = 'instance', type(node.value)
                            else:
                                return parser.parse_node(
                                    node.value,
                                    node_path + [func]
                                )

                Visitor().visit(node)
                if result is None:
                    return None, None
                else:
                    return result

        elif isinstance(node, ast.Attribute):
            kind, value = self.parse_node(node.value, node_path)
            if kind == 'instance':
                return 'instance', getattr(value, node.attr, None)
            else:
                return None, None

        elif isinstance(
                node,
                getattr(ast, 'Constant',
                        (ast.Str, ast.Bytes, ast.Num, ast.NameConstant))):
            return 'instance', ast.literal_eval(node)

        elif isinstance(node, (ast.List, ast.Set, ast.Tuple, ast.Dict)):
            try:
                return 'instance', ast.literal_eval(node)
            except ValueError:
                return 'instance', {
                    ast.List: list,
                    ast.Set: set,
                    ast.Tuple: tuple,
                    ast.Dict: dict
                }.get(type(node), None)

        return None, None

    def find_name(self, target, node_path):
        logging.debug('find_name({!r}, {})'.format(
            target, [ast.dump(node) for node in node_path]))
        parser = self

        class Visitor(ast.NodeVisitor):
            def __init__(self, node_path):
                self.result = None
                self.node_path = node_path

            def generic_visit(self, node):
                if self.result is None:
                    super().generic_visit(node)

            def visit_Import(self, node):
                for name in node.names:
                    if (name.name or name.asname) == target:
                        self.result = 'instance', parser.handle_import(
                            name.name)

            def visit_ImportFrom(self, node):
                for name in node.names:
                    if (name.name or name.asname) == target:
                        self.result = 'instance', parser.handle_fromimport(
                            node.module, name.name)

            def visit_FunctionDef(self, node):
                if node.name == target:
                    self.result = 'func', node

            def visit_ClassDef(self, node):
                if node.name == target:
                    self.result = 'class', node

            def visit_Assign(self, node):
                # logging.debug('find_name:visit_Assign({})'.format(ast.dump(node)))
                for assign_target in node.targets:
                    if isinstance(assign_target, ast.Name):
                        if assign_target.id == target:
                            self.result = parser.parse_node(
                                node.value, self.node_path)

            def visit_Starred(self, node):
                if node.value.id == target:
                    self.result = 'instance', list

        for i in range(len(node_path) - 1, -1, -1):
            visitor = Visitor(node_path[:i + 1])
            visitor.generic_visit(node_path[i])
            result = visitor.result
            if result is not None and result[0] is not None:
                return result
        return None, None

    def get_node_path(self, line, offset):
        path = []
        current_node = self.tree
        while True:
            next_node = None
            path.append(current_node)
            for field, value in ast.iter_fields(current_node):
                if isinstance(value, list):
                    for item in value:
                        if (isinstance(item, ast.AST)
                                and hasattr(item, 'lineno')
                                and hasattr(item, 'col_offset')
                                and ((item.lineno, item.col_offset)
                                     <= (line, offset))):
                            next_node = item

                elif isinstance(value, ast.AST):
                    try:
                        if (value.lineno, value.col_offset) <= (line, offset):
                            next_node = value
                    except AttributeError:
                        pass

            if next_node is not None:
                current_node = next_node
            else:
                return path

    def get_instance_attrs_by_class(self, node):
        class InstanceAttrCollector(ast.NodeVisitor):
            def __init__(self):
                self.results = set()

            def visit_Lambda(self, node):
                pass

            def visit_DictComp(self, node):
                pass

            def visit_GeneratorExp(self, node):
                pass

            def visit_ListComp(self, node):
                pass

            def visit_SetComp(self, node):
                pass

            def visit_ClassDef(self, node):
                pass

            def visit_Attribute(self, node):
                if isinstance(node.value, ast.Name):
                    if node.value.id == 'self':
                        self.results.add(Completion(
                            (node.value.attr, 'attribute')))

        collector = InstanceAttrCollector()
        collector.visit(node)
        return collector.results

    def get_variables(self, node_path):
        # logging.debug('get_variables({})'.format(
        #     [ast.dump(node) for node in node_path])
        # )
        parser = self

        class ScopeVariableCollector(ReversedNodeVisitor):
            """访问一个节点，收集其中定义的所有变量，不包括其中的子作用域"""

            def __init__(self):
                self.results = set()

            def visit_Assign(self, node):
                self.parse_targets(node.targets)

            def visit_With(self, node):
                for item in node.items:
                    if item.optional_vars is not None:
                        self.parse_targets([item.optional_vars])
                self.generic_visit(node)

            def visit_For(self, node):
                self.parse_targets([node.target])
                self.generic_visit(node)

            def visit_Import(self, node):
                for name in node.names:
                    self.register_var(name.asname or name.name, 'module')

            def visit_ImportFrom(self, node):
                for name in node.names:
                    self.register_var(name.asname or name.name)

            def visit_ExceptHandler(self, node):
                self.results.add(node.name)
                self.generic_visit(node)

            def parse_targets(self, targets):
                for target in targets:
                    if isinstance(target, ast.Name):
                        self.register_var(target.id)
                    elif isinstance(target, ast.Starred):
                        self.register_var(target.value.id)
                    elif isinstance(target, ast.Tuple):
                        self.parse_targets(target.elts)

            def visit_FunctionDef(self, node):
                self.register_var(node.name + '()', 'function')

            def visit_ClassDef(self, node):
                self.register_var(node.name, 'class')

            def register_var(self, name, kind='variable'):

                if name is None:
                    return
                if isinstance(name, (list, tuple)):
                    for n in name:
                        self.register_var(n, kind)
                elif isinstance(name, ast.arg):
                    self.results.add(Completion((name.arg, kind)))
                else:
                    self.results.add(Completion((name, kind)))

            def visit_Lambda(self, node):
                pass

            def visit_DictComp(self, node):
                pass

            def visit_GeneratorExp(self, node):
                pass

            def visit_ListComp(self, node):
                pass

            def visit_SetComp(self, node):
                pass

            @classmethod
            def collect(cls, node):
                collector = cls()
                if isinstance(node, (ast.Lambda, ast.FunctionDef)):
                    collector.register_var(node.args.args, 'parameter')
                    collector.register_var(node.args.kwonlyargs, 'parameter')
                    collector.register_var(node.args.vararg, 'parameter')
                    collector.register_var(node.args.kwarg, 'parameter')
                elif isinstance(node, ast.Module):
                    collector.register_var(('__doc__', '__name__'))
                collector.generic_visit(node)
                return collector.results

        results = set()
        for node in reversed(node_path):
            if isinstance(node, (ast.Lambda, ast.FunctionDef, ast.GeneratorExp,
                                 ast.ListComp, ast.SetComp,
                                 ast.DictComp, ast.Module)):
                results.update(ScopeVariableCollector.collect(node))
        return results

    def get_words(self, expr=None, node_path=()):
        parser = self
        expr_parts = expr.strip('()[]{}"\'').split('.')
        try:
            expr_last = expr_parts[-1]
        except IndexError:
            expr_last = ''
        expr_parts = expr_parts[:-1]

        class WordCollector(ast.NodeVisitor):
            def __init__(self):
                self.results = set()

            def visit_Name(self, node):
                if len(expr_parts) == 0:
                    self.register_var(node.id)

            def visit_Attribute(self, node):

                if expr_parts == self.split_attribute(node)[:-1]:
                    self.register_var(node.attr)

            @staticmethod
            def split_attribute(node):
                current_node = node
                parts = []
                while True:
                    if isinstance(current_node, ast.Name):
                        parts.append(current_node.id)
                        break
                    elif isinstance(current_node, ast.Attribute):
                        parts.append(current_node.attr)
                        current_node = current_node.value
                    else:
                        break
                return parts[::-1]

            def register_var(self, name, type='abc'):
                if name is None:
                    return
                if isinstance(name, (list, tuple)):
                    for n in name:
                        if name != expr_last:
                            self.results.add(Completion((n, type)))
                else:
                    if name != expr_last:
                        self.results.add(Completion((name, type)))

            @classmethod
            def collect(cls, tree):
                collector = cls()
                collector.visit(tree)
                return collector.results

        return WordCollector.collect(self.tree)

    @staticmethod
    def get_keywords(expr=None, node_path=()):
        if expr is None or '.' not in expr:
            completions = set()
            for word in keyword.kwlist:
                if word in ('True', 'False', 'None',
                            'continue', 'break', 'except'):
                    completions.add(Completion((word, 'keyword')))
                elif word in ('try', 'else', 'finally'):
                    completions.add(Completion((word + ':', 'keyword')))
                else:
                    completions.add(Completion((word + ' ', 'keyword')))
            return completions
        return set()

    @staticmethod
    def get_builtins(expr=None, node_path=()):
        if expr is None or '.' not in expr:
            return {(Completion((word + '()', 'builtin'))
                     if (callable(getattr(builtins, word))
                         and not isinstance(getattr(builtins, word), type))
                     else Completion((word, 'builtin')))
                    for word in dir(builtins)
                    if '_' not in word or word in ('__debug__', '__import__')}
        return set()

    @staticmethod
    def get_modules(expr=None, node_path=()):
        packages = [] if expr is None else expr.split('.')[:-1]
        suggests = set()
        for path in sys.path:
            files = glob.glob(os.path.join(os.path.join(path, *packages), '*'))
            for file in files:
                if file.endswith(('.pyw', '.pyc', '.pyo', '.pyd')):
                    suggests.add(Completion(
                        (os.path.split(file)[-1][:-4], 'module-name')))
                elif file.endswith('.py'):
                    suggests.add(Completion(
                        (os.path.split(file)[-1][:-3], 'module-name')))
                elif (os.path.isdir(file) and
                      os.path.isfile(os.path.join(file, '__init__.py'))):
                    suggests.add(Completion(
                        (os.path.split(file)[-1], 'package-name')))

        return suggests

    def get_from_imports(self, current_line, node_path=()):
        module = self.from_import_pattern.match(current_line).group('module')
        try:
            self.master.shell.runcode('import {}'.format(module))
            self.master.shell.runcode('_result_ = {}'.format(module))
            module = self.master.shell.locals['_result_']
            suggests = set()
            for key in dir(module):
                value = getattr(module, key)
                if isinstance(value, type):
                    suggests.add(Completion((key, 'class')))
                elif callable(value):
                    suggests.add(Completion((key, 'function')))
                else:
                    suggests.add(Completion((key, 'variable')))
            return suggests
        except Exception:
            return set()

    def get_idle_suggests(self, expr=None, node_path=()):
        if has_idle_autocomplete:
            hp = HyperParser(self.master.window, "insert")
            curline = self.master.text.get("insert linestart", "insert")
            i = j = len(curline)

            while (i and (curline[i - 1] in self.master.identifier_chars
                          or ord(curline[i - 1]) > 127)):
                i -= 1
            comp_start = curline[i:j]
            if i and curline[i - 1] == '.':
                hp.set_index("insert-%dc" % (len(curline) - (i - 1)))
                comp_what = hp.get_expression()
                if not comp_what:
                    return
            else:
                comp_what = ""

            if '(' in comp_what:
                return set()

            comp_lists = self.master.idle_autocomplete.fetch_completions(
                comp_what, COMPLETE_ATTRIBUTES)
            return {Completion((completion, 'idle'))
                    for completion in comp_lists[1]}
        else:
            return set()

    def get_attrs_and_more(self, expr='', node_path=()):
        try:
            node_path = node_path[:]
            hyper_parser = HyperParser(self.master.window, 'insert')
            curline = self.master.text.get('insert linestart', 'insert')
            i = j = len(curline)
            while (i and (curline[i - 1] in self.master.identifier_chars
                          or ord(curline[i - 1]) > 127)):
                i -= 1
            if i and curline[i - 1] == '.':
                hyper_parser.set_index("insert-%dc" % (len(curline) - (i - 1)))
            else:
                return

            expr_string = hyper_parser.get_expression()

            expr = ast.parse(expr_string).body[0].value

            while node_path:
                if ast_eq(node_path[-1], expr):
                    break
                node_path.pop()

            kind, obj = self.parse_node(expr, node_path)

            if kind == 'instance':
                results = set()
                for key in dir(obj) + getattr(obj, '__slots__', []):

                    value = getattr(obj, key, None)
                    if isinstance(value, type):
                        results.add(Completion((key, 'class')))
                    elif isinstance(value, types.GetSetDescriptorType):
                        results.add(Completion((key, 'descriptor')))
                    elif isinstance(obj, type) and isinstance(
                            value, (types.MethodType, classmethod,
                                    staticmethod)):
                        results.add(Completion((key + '()', 'method')))
                    elif callable(value):
                        results.add(Completion((key + '()', 'function')))
                    else:
                        results.add(Completion((key, 'attr')))

                return results
            elif kind == 'class':
                return (self.get_variables([obj])
                        | self.get_instance_attrs_by_class(obj))
            else:
                return set()

        except (LookupError, AttributeError, SyntaxError,
                ValueError, TypeError):
            # traceback_gui.show_traceback()
            return set()

    from_import_pattern = re.compile(
        r"from[ ]+(?P<module>(?:\.|\w)+)[ ]+import (\n|\w|[() ,.])+$")

    def get_suggests(self, expr):
        cursor = self.master.get_cursor()
        # expr = self.master.get_expr(self.master.text.get('1.0', cursor))
        node_path = self.get_node_path(*cursor)
        completions = set()
        current_line = self.master.text.get(
            'insert linestart', 'insert').strip()

        if self.from_import_pattern.match(current_line):
            completions.update(self.get_from_imports(current_line))
        elif current_line.startswith(('import', 'from')):

            completions.update(self.get_modules(expr))
            if current_line.startswith('from'):
                completions.add(Completion(('import ', 'keyword')))

        else:
            if expr is not None and '.' not in expr:

                completions.update(self.get_keywords(expr, node_path))

                completions.update(self.get_builtins(expr, node_path))
                if len(node_path) > 0:
                    completions.update(self.get_variables(node_path))
            elif expr is not None and '.' in expr:
                completions.update(self.get_attrs_and_more(expr, node_path))

                completions.update(self.get_idle_suggests(expr))

            completions.update(self.get_words(expr))

        return sorted(completion
                      for completion in completions
                      if completion.clean_content != self.fix_empty_identifier)


class ReversedNodeVisitor(object):
    def visit(self, node):
        """Visit a node."""
        method = 'visit_' + node.__class__.__name__
        visitor = getattr(self, method, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node):
        """Called if no explicit visitor function exists for a node."""
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in reversed(value):
                    if isinstance(item, ast.AST):
                        self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)


class Completion(tuple):
    @property
    def content(self):
        return self[0]

    @property
    def type(self):
        return self[1]

    @property
    def clean_content(self):
        return self.content.strip('()[]{}:;,')

    def __eq__(self, other):
        return self.clean_content == other.clean_content

    def __hash__(self):
        return hash(self.clean_content)

    def __repr__(self):
        return 'Completion(({!r}, {!r}))'.format(self.content, self.type)

    def __lt__(self, other):
        self_suffix_underlines = 0
        for char in self.content:
            if char != '_':
                break
            else:
                self_suffix_underlines += 1

        other_suffix_underlines = 0
        for char in other.content:
            if char != '_':
                break
            else:
                other_suffix_underlines += 1

        if self_suffix_underlines != other_suffix_underlines:
            return self_suffix_underlines < other_suffix_underlines
        else:
            return (self.content[self_suffix_underlines:]
                    < other.content[other_suffix_underlines:])


class CodeCompletionWindow:
    def __init__(self, parent: MyIdleExt, master=None):
        self.parent = parent
        self.window = tkinter.Toplevel(master)
        self.window.overrideredirect(True)
        self.window.withdraw()

        # Set up completion_list
        self.style = tkinter.ttk.Style(self.window)
        self.style.configure('completion_list.Treeview', font=(
            idleConf.GetOption('main', 'EditorWindow', 'font'),
            idleConf.GetOption('main', 'EditorWindow', 'font-size')
        ))
        self.completion_list = tkinter.ttk.Treeview(
            self.window,
            columns=['completion', 'type'],
            show='headings',
            style='completion_list.Treeview'
        )
        self.completion_list.column('completion', stretch=True)
        self.completion_list.column('type', width=120, anchor='e')
        self.completion_list.heading('completion', text='completion')
        self.completion_list.heading('type', text='type')

        color_reg = re.compile(
            r"^color_(?P<tag>.+)_(?P<fg_or_bg>fg|bg|foreground|background)$")
        for key, value in idleConf.defaultCfg['extensions'].items('MyIdleExt'):
            match = color_reg.match(key)
            if match:
                options = {
                    {'fg': 'foreground', 'bg': 'background'}.get(
                        match.group('fg_or_bg'),
                        match.group('fg_or_bg')
                    ):
                    value
                }
                self.completion_list.tag_configure(
                    match.group('tag'), **options)

        self.completion_list.pack(side='left', fill='both')
        self.scrollbar = tkinter.ttk.Scrollbar(
            self.window, command=self.completion_list.yview)
        self.completion_list['yscrollcommand'] = self.scrollbar.set
        self.scrollbar.pack(side='right', fill='y')

        self.is_active = False

        self.values = []
        self.bindings = []
        self.suggests = []
        self.start_index = None

    def activate(self):

        if self.is_active:
            return

        self.parent_text_bind('<Up>', self.prev, add=True)
        self.parent_text_bind('<Down>', self.next, add=True)
        self.parent_text_bind(
            '<KeyRelease>', self.filter_completions, add=True)
        self.parent_text_bind('<Return>', self.choose, add=True)
        self.parent_text_bind('<BackSpace>', self.update_event, add=True)
        self.window.wm_deiconify()

        self.is_active = True

        self.start_index = self.get_word()[0]

        text = self.parent.text
        text.see(self.start_index)
        x, y, cx, cy = self.parent.text.bbox(self.start_index)
        acw = self.window
        acw_width, acw_height = acw.winfo_width(), acw.winfo_height()
        text_width, text_height = text.winfo_width(), text.winfo_height()
        new_x = text.winfo_rootx() + min(x, text_width - acw_width)
        new_y = text.winfo_rooty() + y
        if (text_height - (y + cy) >= acw_height  # enough height below
                or y < acw_height):  # not enough height above
            # place acw below current line
            new_y += cy
        else:
            # place acw above current line
            new_y -= acw_height
        acw.wm_geometry("+%d+%d" % (new_x, new_y))

        self.update_event()

    def deactivate(self):

        if not self.is_active:
            return

        for args in self.bindings:
            self.parent.text.unbind(*args)
        self.bindings.clear()

        for item in self.completion_list.get_children():
            self.completion_list.delete(item)

        self.window.withdraw()

        self.is_active = False

    def choose(self, event):

        if not self.is_active:
            return None
        print('choosed')
        try:
            values = self.completion_list.item(
                self.completion_list.selection(), 'values')

            value = values[0]
            left, right, word = self.get_word()

            self.parent.text.delete(left, right)
            self.parent.text.insert('insert', value)
            if value.endswith('()'):
                self.parent.text.mark_set('insert', 'insert-1c')
            self.deactivate()
            return 'break'
        except IndexError:
            return 'break'

    def update_event(self, event=None):

        self.window.after_idle(self.filter_completions)

    def filter_completions(self, event=None):

        if not self.is_active:
            return None
        if event is not None and event.char == '\r':  # 绑定出了问题，回车键转由choose处理

            # 由于这里是KeyRelease事件，text已经换行，需要先删除换行符
            self.parent.text.delete('insert-1c', 'insert')
            return self.choose(event)

        left, right, word = self.get_word()
        if left != self.start_index:
            print('start index not match')
            self.deactivate()
            return None

        try:
            selected = self.completion_list.item(
                self.completion_list.selection(), 'values')[0]
        except IndexError:
            selected = (None, None)

        for item in self.completion_list.get_children():
            self.completion_list.delete(item)

        suggests = [suggest for suggest in self.suggests
                    if match_words(word, list(yield_words(suggest.content)))]

        suggests.sort()
        for suggest in suggests:

            element = self.completion_list.insert(
                '', 'end', values=suggest, tags=(suggest.type,))

            # self.completion_list.item(element, tags=(suggest.type,))
            if suggest.content == selected:
                self.completion_list.selection_set(element)

        selection = self.completion_list.selection()
        if selection == '' or selection == ():
            try:
                self.completion_list.selection_set(
                    self.completion_list.get_children()[0])
            except IndexError:
                self.deactivate()

        print('finished')
        return None

    def get_word(self):
        cursor = self.parent.get_cursor()
        this_line = self.parent.text.get(join_index(cursor.row, 0), cursor)
        assert isinstance(this_line, str)
        left_index = cursor.column - 1
        for left_index in range(cursor.column - 1, -1, -1):
            if (not (this_line[left_index].isidentifier()
                     or this_line[left_index].isdigit())):
                break
        else:
            left_index -= 1
        left_index += 1

        return (TextIndex((cursor.row, left_index)),
                cursor, this_line[left_index:cursor.column])

    def parent_text_bind(self, sequence, func=None, add=True):
        self.bindings.append(
            (sequence, self.parent.text.bind(sequence, func, add=add)))

    def prev(self, event):
        if not self.is_active:
            return None
        item = self.completion_list.prev(self.completion_list.selection())
        self.completion_list.selection_set(item)
        self.completion_list.see(item)
        return 'break'

    def next(self, event):
        if not self.is_active:
            return None
        selected = self.completion_list.selection()
        if selected:
            item = self.completion_list.next(self.completion_list.selection())
            self.completion_list.selection_set(item)
            self.completion_list.see(item)
        else:
            try:
                self.completion_list.selection_set(
                    self.completion_list.get_children()[0])
            except IndexError:
                self.deactivate()
        return 'break'


def yield_words(identifier, word_regex=re.compile(r"([A-Z]+_+|[a-z]+_+|"
                                                  r"[A-Z]?[a-z]*|[0-9]+|"
                                                  r"[~A-Za-z0-9_])")):
    _words = word_regex.findall(identifier)
    for word in _words:
        if '_' in word:
            underlines_begin = word.index('_')
            yield word[:underlines_begin]
            yield word[underlines_begin:]
        elif word != '':
            yield word


def match_words(pattern, words):
    if pattern == '':
        return True

    if len(words) == 0:
        # return pattern == ''
        return False

    for pattern_index in range(len(pattern) + 1):
        if words[0].startswith(pattern[:pattern_index]):
            if match_words(pattern[pattern_index:], words[1:]):
                return True
        else:
            return False
