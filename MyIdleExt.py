"""
MyIdleExt -- My Idle Extension
------------------------------
This is a idle extension which provides code completion, brackets/quotes completion and more features.
This file should be loaded by idlelib.
In this way, it will provide the features mentioned above.
Otherwise, if you run this file as `__main__` (Run directly),
you can do some operations such as install and uninstall.
"""
import re
import os
import sys

version = _version_ = '0.2.0'

config_extension_def = """
[MyIdleExt]
enable=1
enable_editor=1
enable_shell=0

[MyIdleExt_cfgBindings]
format-pep8=<Control-l>

"""


def on_run_as_main():
    import shutil
    import traceback
    import argparse
    import configparser

    def find_idlelib():
        for path in sys.path:
            try:
                for directory in os.listdir(path):
                    if directory == 'idlelib' and os.path.isdir(os.path.join(path, directory)):
                        config_extension_filename = os.path.join(path, directory, 'config-extensions.def')
                        if os.path.isfile(config_extension_filename):
                            return os.path.join(path, 'idlelib')
            except OSError:
                pass
        print('`idlelib` not found. Try to specified the path of it. ')
        sys.exit()

    arg_parser = argparse.ArgumentParser('MyIdleExt', description=__doc__)
    subparsers_group = arg_parser.add_subparsers(title='Commands', dest='command', metavar='<command>')

    command_install = subparsers_group.add_parser('install', help='Install MyIdleExt for your idle. '
                                                                  'You might need to restart idle to apply. ')
    command_install.add_argument('--path', help='The path of idlelib to install MyIdleExt. '
                                                'If is not specified, program will search it in `sys.path`. ',
                                 default='')
    command_install.add_argument('--sure', action='store_const', const=True, default=False,
                                 help='If it is already installed, do not ask if the user want to overwrite. ')

    command_uninstall = subparsers_group.add_parser('uninstall', help='Uninstall MyIdleExt for your idle')
    command_uninstall.add_argument('--path', help='The path of idlelib to uninstall MyIdleExt. '
                                                  'If is not specified, program will search it in `sys.path`. ',
                                   default='')
    command_uninstall.add_argument('--sure', action='store_const', const=True, default=False,
                                   help='Do not ask if the user really want to uninstall. ')

    subparsers_group.add_parser('version', help='Show the version of MyIdleExt. ')

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

    def install(this, args):
        if args.path == '':
            args.path = find_idlelib()
        if is_installed(args.path) and not args.sure:
            if not ask_yes_no('MyIdleExt looks already installed in "{}". '
                              'Are you sure to overwrite?'.format(args.path)):
                print('Operation canceled. ')
                return
        shutil.copy(this, os.path.join(args.path, 'MyIdleExt.py'))
        default_config = configparser.ConfigParser()
        default_config.read_string(config_extension_def)
        idle_config = configparser.ConfigParser()
        idle_config.read(os.path.join(args.path, 'config-extensions.def'))
        for section in default_config.sections():
            if not idle_config.has_section(section):
                idle_config.add_section(section)
            for key, value in default_config.items(section):
                idle_config.set(section, key, value)

        with open(os.path.join(args.path, 'config-extensions.def'), 'w') as fp:
            idle_config.write(fp)

        print('MyIdleExt installed successfully. ')

    def uninstall(this, args):
        if args.path == '':
            args.path = find_idlelib()
        if not is_installed(args.path):
            print('MyIdleExt is not installed. ')
            return
        if not args.sure:
            if not ask_yes_no('Are you sure to uninstall MyIdleExt in "{}"?'.format(args.path)):
                print('Operation canceled. ')
        os.remove(os.path.join(args.path, 'MyIdleExt.py'))
        default_config = configparser.ConfigParser()
        default_config.read_string(config_extension_def)
        idle_config = configparser.ConfigParser()
        idle_config.read(os.path.join(args.path, 'config-extensions.def'))
        for section in default_config.sections():
            if idle_config.has_section(section):
                idle_config.remove_section(section)

        with open(os.path.join(args.path, 'config-extensions.def'), 'w') as fp:
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
              '`<command> -h` for help with the specifiesd command, or `quit` to quit ')
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
                    args = arg_parser.parse_args([arg.strip('"') for arg in pattern.findall(command) if arg.strip()])
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

import string
import tkinter
import tkinter.messagebox
import tkinter.ttk
import tempfile
import ast
import inspect
import glob
from code import InteractiveInterpreter
import keyword
import builtins

try:
    from idlelib.config import idleConf
except ImportError:
    from idlelib.configHandler import idleConf

try:
    from idlelib.editor import EditorWindow
except ImportError:
    from idlelib.EditorWindow import EditorWindow

try:
    from idlelib.autocomplete import AutoComplete, HyperParser, ATTRS as COMPLETE_ATTRIBUTES
except ImportError:
    from idlelib.AutoComplete import AutoComplete, HyperParser, COMPLETE_ATTRIBUTES

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
        self.text.bind(idleConf.GetOption('extensions', 'MyIdleExt_cfgBindings', 'format-pep8'), self.format_pep8)

        self.completion = CodeCompletionWindow(self, self.window.top)

        self.text.bind('<Tab>', self.open_completion)
        self.text.bind('<Key>', self.handle_key, add=True)

        self.idle_autocomplete = AutoComplete(editwin)

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
            #     if two_chars_before[1] == '\\' and two_chars_before[0] != '\\':
            #         return  # 转义
            #     else:
            #         return  # 闭合该字符串
            #
            # else:
            #     return
            return  # 以上每种情况都不做处理

    def handle_backspace(self, event):
        # print('handle_backspace')
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

    def handle_key(self, event):
        # print(vars(event))
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

            self.open_completion()

        # elif event.char in '{[(\'"':
        #     self.expand_brackets_or_quotes(event)
        #
        # elif event.char in ')]}':
        #     self.handle_close_bracket(event)

    def handle_tab(self, event):
        cursor = self.get_cursor()
        text_before = self.text.get(cursor.line_start, cursor).strip()
        if text_before != '' and (self.completion.get_word() != '' or text_before[-1] == '.'):
            self.open_completion()
            return 'break'

    @staticmethod
    def get_expr(code):
        open_brackets = {
            '(': ')',
            '[': ']',
            '{': '}'
        }
        close_brackets = {
            ')': '(',
            ']': '[',
            '}': '{'
        }

        stack = []
        string_quote = None
        start_index = len(code) - 1
        for start_index in range(len(code) - 1, -1, -1):
            char = code[start_index]
            if string_quote is None:
                if char in close_brackets.values():
                    stack.append(char)

                elif char in open_brackets.values():
                    if len(stack) >= 1:
                        from_stack = stack[-1]
                        if char == close_brackets[from_stack]:
                            stack.pop()
                        else:
                            start_index = min(start_index + 1, len(code) - 1)
                            break
                    else:
                        break

                elif char in ('"', "'"):
                    if code[start_index:start_index + 3] == char * 3:
                        string_quote = char * 3
                    else:
                        string_quote = char

                elif char in ':;':
                    break

            else:
                if char == string_quote and not is_escape(code[:start_index]):
                    string_quote = None

                if (char in string_quote and code[start_index:start_index + 3] == string_quote
                        and not is_escape(code[:start_index])):
                    string_quote = None

        if string_quote is not None or len(stack) != 0:
            return ''

        return code[start_index:].strip(':, ')

    def get_suggests(self, expr=None):
        code = self.text.get('1.0', 'end')
        parser = CodeParser(code, self)
        parser.parse_as_more_as_possible(self.get_cursor().row)
        parser.prepare()
        return parser.get_suggests(expr)

    def open_completion(self, event=None):
        self.completion.suggests = self.get_suggests(self.get_expr(self.text.get('1.0', 'insert')))
        self.completion.activate()
        return 'break'


class CodeParser:
    def __init__(self, code, master: MyIdleExt):
        self.code = code
        self.tree = self.parse_as_more_as_possible()
        self.imports = []
        self.fromimports = []

        self.master = master

    def parse_as_more_as_possible(self, end_lineno=None):
        code = self.code
        code_lines = code.splitlines()
        end_lineno = len(code_lines) if end_lineno is None else end_lineno
        while True:
            try:
                tree = ast.parse('\n'.join(code_lines[:end_lineno]))
            except SyntaxError as syntax_error:
                end_lineno = syntax_error.lineno - 1
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

    def find_name(self, target, lineno=None):
        if lineno is None:
            lineno = self.code.count('\n')

        # Search in imports and fromimports
        for import_ in reversed(self.imports):
            if import_.lineno > lineno:
                continue

            for target in import_.names:
                import_name = target.asname or target.name
                if import_name == target:
                    return 'import', target.name

        for fromimport in reversed(self.fromimports):
            if fromimport.lineno > lineno:
                continue

            for target in fromimport.names:
                import_name = target.asname or target.name
                if import_name == target:
                    return 'from', fromimport.module, target.name

        # Search others
        parser = self

        class Visitor(ast.NodeVisitor):
            def __init__(self):
                self.result = None

            def visit_FunctionDef(self, node):
                if node.name == target:
                    self.result = 'func', node

            def visit_Assign(self, node):
                if node.name == target:
                    self.result = 'var', node

        visitor = Visitor()
        visitor.visit(self.tree)
        result = visitor.result
        return result

    @staticmethod
    def get_return_type(func):
        if isinstance(func, type):
            return func
        elif callable(func):
            try:
                return inspect.signature(func).return_annotation
            except ValueError:
                return None
        else:
            return None

    def get_words(self, expr=None):
        parser = self

        class Visitor(ast.NodeVisitor):
            def __init__(self):
                self.results = set()

            def visit_FunctionDef(self, node):
                self.results.add(node.name)
                self.results.update(node.args.args)
                self.results.update(node.args.kwonlyargs)
                self.results.add(node.args.vararg)
                self.results.add(node.args.kwarg)

            def visit_Lambda(self, node):
                self.results.add(node.name)
                self.results.update(node.args.args)
                self.results.update(node.args.kwonlyargs)
                self.results.add(node.args.vararg)
                self.results.add(node.args.kwarg)

            def visit_ClassDef(self, node):
                self.results.add(node.name)

            def visit_Assign(self, node):
                self.parse_targets(node.targets)

            def visit_With(self, node):
                for item in node.items:
                    if item.optional_vars is not None:
                        self.parse_targets([item.optional_vars])

            def visit_For(self, node):
                self.parse_targets([node.target])

            def visit_Import(self, node):
                for name in node.names:
                    self.results.add(name.asname or name.name)

            def visit_ImportFrom(self, node):
                for name in node.names:
                    self.results.add(name.asname or name.name)

            def visit_ExceptHandler(self, node):
                self.results.add(node.name)

            def parse_targets(self, targets):
                for target in targets:
                    if isinstance(target, ast.Name):
                        self.results.add(target.id)
                    elif isinstance(target, ast.Tuple):
                        self.parse_targets(target.elts)

        visitor = Visitor()
        visitor.visit(self.tree)
        results = visitor.results

        if None in results:
            results.remove(None)

        return {Completion((word, 'abc')) for word in results}

    @staticmethod
    def get_keywords(expr=None):
        if expr is None or '.' not in expr:
            completions = set()
            for word in keyword.kwlist:
                if word in ('True', 'False', 'None', 'continue', 'break', 'except'):
                    completions.add(Completion((word, 'keyword')))
                elif word in ('try', 'else', 'finally'):
                    completions.add(Completion((word + ':', 'keyword')))
                else:
                    completions.add(Completion((word + ' ', 'keyword')))
            return {(Completion((word + ' ', 'keyword'))
                     if word not in ('True', 'False', 'None', 'continue', 'break')
                     else Completion((word, 'keyword')))
                    for word in keyword.kwlist}
        return set()

    @staticmethod
    def get_builtins(expr=None):
        if expr is None or '.' not in expr:
            return {(Completion((word + '()', 'builtin'))
                     if callable(getattr(builtins, word)) and not isinstance(getattr(builtins, word), type)
                     else Completion((word, 'builtin')))
                    for word in dir(builtins)
                    if '_' not in word or word in ('__debug__', '__import__')}
        return set()

    @staticmethod
    def get_modules(self, expr=None):
        packages = [] if expr is None else expr.split('.')[:-1]
        suggests = set()
        for path in sys.path:
            files = glob.glob(os.path.join(os.path.join(path, *packages), '*'))
            for file in files:
                if file.endswith(('.pyw', '.pyc', '.pyo', '.pyd')):
                    suggests.add(Completion((os.path.split(file)[-1][:-4], 'module')))
                elif file.endswith('.py'):
                    suggests.add(Completion((os.path.split(file)[-1][:-3], 'module')))
                elif os.path.isdir(file) and os.path.isfile(os.path.join(file, '__init__.py')):
                    suggests.add(Completion((os.path.split(file)[-1], 'package')))

        return suggests

    def get_idle_suggests(self, expr=None):
        hp = HyperParser(self.master.window, "insert")
        curline = self.master.text.get("insert linestart", "insert")
        i = j = len(curline)

        while i and (curline[i - 1] in self.master.identifier_chars or ord(curline[i - 1]) > 127):
            i -= 1
        comp_start = curline[i:j]
        if i and curline[i - 1] == '.':
            hp.set_index("insert-%dc" % (len(curline) - (i - 1)))
            comp_what = hp.get_expression()
            if not comp_what:
                return
        else:
            comp_what = ""

        comp_lists = self.master.idle_autocomplete.fetch_completions(comp_what, COMPLETE_ATTRIBUTES)
        return {Completion((completion, 'idle')) for completion in comp_lists[1]}

    def get_suggests(self, expr=None):
        completions = set()
        current_line = self.master.text.get('insert linestart', 'insert').strip()
        if current_line.startswith(('import', 'from')):
            completions.update(self.get_modules(expr))
        else:
            if expr is not None and '.' not in expr:
                completions.update(self.get_keywords(expr))
                completions.update(self.get_builtins(expr))
            elif expr is not None and '.' in expr:
                completions.update(self.get_idle_suggests(expr))
            completions.update(self.get_words(expr))
        return completions


class Completion(tuple):
    @property
    def content(self):
        return self[0]

    @property
    def type(self):
        return self[1]

    def __eq__(self, other):
        return self.content == other.content

    def __hash__(self):
        return hash(self.content)

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
            return self.content[self_suffix_underlines:] < other.content[other_suffix_underlines:]


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
        self.completion_list.column('type', width=100, anchor='e')
        self.completion_list.heading('completion', text='completion')
        self.completion_list.heading('type', text='type')

        theme = idleConf.GetOption('main', 'Theme', 'name')
        self.completion_list.tag_configure('keyword', foreground=idleConf.GetHighlight(theme, 'keyword')['foreground'])
        self.completion_list.tag_configure('builtin', foreground=idleConf.GetHighlight(theme, 'builtin')['foreground'])
        self.completion_list.tag_configure('abc', foreground='#333333')
        self.completion_list.tag_configure('idle', foreground='#ff00ff')
        self.completion_list.tag_configure('module', foreground='#808040')
        self.completion_list.tag_configure('package', foreground='#808040')
        # print(self.completion_list.tag_configure('package'))

        self.completion_list.pack(side='left', fill='both')
        self.scrollbar = tkinter.ttk.Scrollbar(self.window, command=self.completion_list.yview)
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
        self.window.wm_deiconify()
        self.parent_text_bind('<Up>', self.prev, add=True)
        self.parent_text_bind('<Down>', self.next, add=True)
        self.parent_text_bind('<Return>', self.choose, add=True)
        self.parent_text_bind('<KeyRelease>', self.filter_completions, add=True)
        self.parent_text_bind('<BackSpace>', self.update_event, add=True)

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
        for args in self.bindings:
            self.parent.text.unbind(*args)
        self.bindings.clear()

        for item in self.completion_list.get_children():
            self.completion_list.delete(item)

        self.window.withdraw()

        self.is_active = False

    def choose(self, event):
        try:
            values = self.completion_list.item(self.completion_list.selection(), 'values')

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
        left, right, word = self.get_word()
        if left != self.start_index:
            self.deactivate()
            return

        try:
            selected = self.completion_list.item(self.completion_list.selection(), 'values')[0]
        except IndexError:
            selected = (None, None)

        for item in self.completion_list.get_children():
            self.completion_list.delete(item)

        suggests = [suggest for suggest in self.suggests
                    if match_words(word, list(yield_words(suggest.content)))]

        suggests.sort()
        for suggest in suggests:
            # print(suggest.type)
            element = self.completion_list.insert('', 'end', values=suggest, tags=(suggest.type,))
            # print(self.completion_list.item(element, 'tags'))
            # self.completion_list.item(element, tags=(suggest.type,))
            if suggest.content == selected:
                self.completion_list.selection_set(element)

        selection = self.completion_list.selection()
        if selection == '' or selection == ():
            try:
                self.completion_list.selection_set(self.completion_list.get_children()[0])
            except IndexError:
                self.deactivate()

    def get_word(self):
        cursor = self.parent.get_cursor()
        this_line = self.parent.text.get(join_index(cursor.row, 0), cursor)
        assert isinstance(this_line, str)
        left_index = cursor.column - 1
        for left_index in range(cursor.column - 1, -1, -1):
            if not (this_line[left_index].isidentifier() or this_line[left_index].isdigit()):
                break
        else:
            left_index -= 1
        left_index += 1

        return TextIndex((cursor.row, left_index)), cursor, this_line[left_index:cursor.column]

    def parent_text_bind(self, sequence, func=None, add=True):
        self.bindings.append((sequence, self.parent.text.bind(sequence, func, add=add)))

    def prev(self, event):
        item = self.completion_list.prev(self.completion_list.selection())
        self.completion_list.selection_set(item)
        self.completion_list.see(item)
        return 'break'

    def next(self, event):
        selected = self.completion_list.selection()
        if selected:
            item = self.completion_list.next(self.completion_list.selection())
            self.completion_list.selection_set(item)
            self.completion_list.see(item)
        else:
            try:
                self.completion_list.selection_set(self.completion_list.get_children()[0])
            except IndexError:
                self.deactivate()
        return 'break'


def yield_words(identifier, word_regex=re.compile(r"([A-Z]+_+|[a-z]+_+|[A-Z]?[a-z]*|[0-9]+|[~A-Za-z0-9_])")):
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
