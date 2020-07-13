"""My Idle Extension"""
import re
import os
import sys
import textwrap
import string
import tkinter
import tkinter.messagebox
import tkinter.ttk
import tempfile
import ast
import inspect
from code import InteractiveInterpreter
import keyword
import builtins
from idlelib.configHandler import idleConf

try:
    from idlelib.editor import EditorWindow
except ImportError:
    from idlelib.EditorWindow import EditorWindow

# from typing import *

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

        # self.code_parser = CodeParser(editwin.text.get('1.0', 'end'))
        self.completion = CodeCompletionWindow(self, editwin.top)

        self.text.bind('<Tab>', self.open_completion)
        self.text.bind('<Key>', self.handle_key, add=True)
        # self.text.bind('<BackSpace>', self.handle_backspace, add=True)

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
        parser = CodeParser(code)
        parser.parse_as_more_as_possible(self.get_cursor().row)
        parser.prepare()
        return parser.get_suggests(expr)

    def open_completion(self, event=None):
        self.completion.suggests = self.get_suggests(self.get_expr(self.text.get('1.0', 'insert')))
        self.completion.activate()
        return 'break'

    # def get_suggests(self, name: str):
    #     if name.startswith('.'):
    #         # NotImplemented
    #         return
    #     self.code_parser.update(self.text.get('1.0', 'end'))
    #     object_name, pattern = name.rsplit('.', 1)
    #     self.code_parser.interpreter.runcode('__result__ = ' + object_name)
    #     obj = self.code_parser.interpreter.locals['__result__']
    #     attrs = dir(obj)
    #     pattern = re.compile(r'\w*'.join(pattern))
    #     possible_names = [attr for attr in attrs if pattern.match(attr)]
    #     return possible_names

    # def handle_dot(self, event):
    #     cursor = self.get_cursor()
    #     if self.position_in_tags(cursor):
    #         return
    #
    #     this_line = self.text.get(join_index(cursor.row, '0'), join_index(cursor.row, 'end'))
    #
    #     pattern = re.compile(r"""
    #     \.?
    #     (?:\w(?<![0-9]) \w* \.)*
    #     (?:\w(?<![0-9]) \w*)?""", re.VERBOSE)
    #
    #     start = 0
    #     while start < len(this_line):
    #         match = pattern.search(this_line, start)
    #         if match is not None:
    #             left, right = match.span()
    #             if left <= cursor <= right:
    #                 break
    #         start = match.span()[1]
    #     else:
    #         return
    #
    #     suggests = self.get_suggests(match.group())
    #     if len(suggests) == 0:
    #         return
    #     else:
    #         suggests.sort()


class CodeParser:
    def __init__(self, code):
        self.code = code
        self.tree = self.parse_as_more_as_possible()
        self.imports = []
        self.fromimports = []

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
            return {Completion((word + ' ', 'keyword')) for word in keyword.kwlist}
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

    def get_suggests(self, expr=None):
        completions = set()
        completions.update(self.get_keywords(expr))
        completions.update(self.get_builtins(expr))
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
        self.completion_list.tag_configure('keyword', foreground=idleConf.GetHighlight(theme, 'keyword', 'fg'))
        self.completion_list.tag_configure('builtin', foreground=idleConf.GetHighlight(theme, 'builtin', 'fg'))
        self.completion_list.tag_configure('abc', foreground='#333333')

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

        for suggest in self.suggests:
            if match_words(word, list(yield_words(suggest.content))):
                element = self.completion_list.insert('', 'end', values=suggest, tags=(suggest.type,))
                if suggest.content == selected:
                    self.completion_list.selection_set(element)

        if self.completion_list.selection() == '':
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
