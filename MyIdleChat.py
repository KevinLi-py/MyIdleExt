"""
MyIdleChat -- My Idle Extension
-------------------------------
This is a idle extension which provides chat service.
"""

import re
import io
import os
import sys
import hashlib
import random
import itertools
import socket
import binascii
import struct
import base64
import threading
import json
import logging
from collections.abc import Sequence, MutableSequence

version = _version_ = '0.1.0'

config_extension_def = """
[MyIdleChat]
enable=True
enable_editor=True
enable_shell=False

[MyIdleChat_cfgBindings]
open-chat-window=<Ctrl-Shift-C>
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

    arg_parser = argparse.ArgumentParser('MyIdleChat', description=__doc__)
    subparsers_group = arg_parser.add_subparsers(
        title='Commands', dest='command', metavar='<command>')

    command_install = subparsers_group.add_parser(
        'install',
        help='Install MyIdleChat for your idle. '
             'You might need to restart idle to apply. '
    )
    command_install.add_argument(
        '--path',
        help='The path of idlelib to install MyIdleChat. '
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
        'uninstall', help='Uninstall MyIdleChat for your idle')
    command_uninstall.add_argument(
        '--path',
        help='The path of idlelib to uninstall MyIdleChat. '
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
                                help='Show the version of MyIdleChat. ')

    server_parser = subparsers_group.add_parser('server', help='Run as server. ')
    visibility = server_parser.add_mutually_exclusive_group()
    visibility.add_argument('--visible')
    visibility.add_argument('--invisible')
    server_parser.add_argument('--password')

    def is_installed(idle_path):
        return os.path.isfile(os.path.join(idle_path, 'MyIdleChat.py'))

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
            if not ask_yes_no('MyIdleChat looks already installed in "{}". '
                              'Are you sure to overwrite?'.format(args.path)):
                print('Operation canceled. ')
                return
        try:
            shutil.copy(this, os.path.join(args.path, 'MyIdleChat.py'))
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

        print('MyIdleChat installed successfully. ')

    def uninstall(this, args):
        if args.path == '':
            args.path = find_idlelib()
        if not is_installed(args.path):
            print('MyIdleChat is not installed. ')
            return
        if not args.sure:
            if not ask_yes_no('Are you sure to uninstall MyIdleChat in "{}"?'
                                      .format(args.path)):
                print('Operation canceled. ')
        os.remove(os.path.join(args.path, 'MyIdleChat.py'))
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

        print('MyIdleChat uninstalled successfully. ')

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


if __name__ == '__main__' and False:
    on_run_as_main()
    sys.exit()


class MyIdleChat:
    menudefs = [
        ('file', [
            (),
            ("Open Chat Window", "<<open-chat-window>>"),
        ])
    ]


class MySocket:
    CONNECT_MSG = b'micp.connect'
    START_HANDSHAKE_MSG = b'micp.start_handshake'
    FINISH_HANDSHAKE_MSG = b'micp.finish_handshake'

    def __init__(self, sock=None, aes=None):
        self.sock = sock or socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.aes = aes
        self.sent_msg_count = 0
        self.received_msg_count = 0
        self.types = []

    def _raw_sock_recv(self, size, sock=None):
        if sock is None:
            sock = self.sock
        received = bytearray()
        while len(received) < size:
            received += sock.recv(size - len(received))
        return received

    @staticmethod
    def _expect(expected, got):
        if expected != got:
            raise MySocketError("Expect {!r}, but received {!r}".format(expected, got),
                                expected, got)

    def connect(self, address):
        logging.debug('tcp connecting')
        self.sock.connect(address)
        logging.debug('handshaking')
        key = self.client_handshake()
        logging.debug('handshake finished')
        # The key is 256-bit, but our AES only supports 128-bit key
        secret_key = binascii.unhexlify(hashlib.md5(binascii.unhexlify(key.encode())).hexdigest().encode())
        logging.debug('secret key: {!r}'.format(secret_key))
        self.aes = AES(bytearray(secret_key))

    def accept(self):
        while True:
            logging.debug('tcp accepting')
            sock, addr = self.sock.accept()
            sock.settimeout(4)
            try:
                logging.debug('handshaking')
                key = self.server_handshake(sock)
            except (socket.error, MySocketError) as exc:
                logging.warning('handshake failed with {!r}'.format(exc))
                continue
            else:
                logging.debug('handshake finished')
                # The key is 256-bit, but our AES only supports 128-bit key
                secret_key = binascii.unhexlify(hashlib.md5(binascii.unhexlify(key.encode())).hexdigest().encode())
                logging.debug('secret key: {!r}'.format(secret_key))
                sock.setblocking(True)
                return MySocket(sock, AES(bytearray(secret_key))), addr

    def client_handshake(self):
        diffie_hellman = DiffieHellman()

        logging.debug('sending connect request')
        self.sock.send(self.CONNECT_MSG.ljust(32, b'\0'))

        logging.debug('receiving dh response')
        response = self._raw_sock_recv(32).strip(b'\0')
        self._expect(self.START_HANDSHAKE_MSG, response)

        logging.debug('sending public key')
        client_public_key = diffie_hellman.gen_public_key()
        self.sock.send(client_public_key.to_bytes(256, 'big'))

        logging.debug('receiving public key')
        server_public_key = int.from_bytes(self._raw_sock_recv(256), 'big')

        logging.debug('sending finish dh')
        self.sock.send(self.FINISH_HANDSHAKE_MSG.ljust(32, b'\0'))

        logging.debug('receiving finish dh')
        response = self._raw_sock_recv(32).strip(b'\0')
        self._expect(self.FINISH_HANDSHAKE_MSG, response)

        return diffie_hellman.gen_shared_key(server_public_key)

    def server_handshake(self, sock):
        diffie_hellman = DiffieHellman()

        logging.debug('receiving response')
        response = self._raw_sock_recv(32, sock=sock).strip(b'\0')
        self._expect(self.CONNECT_MSG, response)

        logging.debug('sending dh request')
        sock.send(self.START_HANDSHAKE_MSG.ljust(32, b'\0'))

        logging.debug('receiving public key')
        client_public_key = int.from_bytes(self._raw_sock_recv(256, sock=sock), 'big')

        logging.debug('sending public key')
        server_public_key = diffie_hellman.gen_public_key()
        sock.send(server_public_key.to_bytes(256, 'big'))

        logging.debug('sending finish dh')
        response = self._raw_sock_recv(32, sock=sock).strip(b'\0')
        self._expect(self.FINISH_HANDSHAKE_MSG, response)

        logging.debug('receiving finish dh')
        sock.send(self.FINISH_HANDSHAKE_MSG.ljust(32, b'\0'))

        return diffie_hellman.gen_shared_key(client_public_key)

    def bind(self, addr):
        self.sock.bind(addr)

    def listen(self, backlog=5):
        self.sock.listen(backlog)

    def _send(self, raw_content, content_type, flag, message_id=None):
        """
        use the protocol to send some bytes.
        message-format: header + content
        header-format:  (28 bytes)
            "<" + T + F + L + I + V + ">"
            T: content type  (c|char)
            F: flag  (B|unsigned char)
            L: encoded-content length  (Q|unsigned long long)
            I: message-id  (Q|unsigned long long)
            V: last 8 bytes of md5-hash of decoded-decrypted-content
               (8s|bytes of length 8)

        content-format:  ((L + 2) bytes)
            "{" + C + "}"
            C: content  (variable-length base64-encoded encrypted bytes, length = L)

        For messages to send, F should be 0
        For responses to tell the message is received, F should be 1.
        And in this case, message_id should be the received message id.
        content and verify should be empty.
        content_flag should be b'\0'
        """
        verify = binascii.unhexlify(hashlib.md5(raw_content).hexdigest().encode())[-8:]
        content = base64.encodebytes(self.aes.encrypt(bytearray(raw_content)))
        if message_id is None:
            message_id = self.sent_msg_count
        self.sent_msg_count += 1
        content_length = len(content)
        header = struct.pack('>cBQQ8s', content_type, flag, content_length, message_id, verify)
        self.sock.send(b'<' + header + b'>')
        self.sock.send(b'{' + content + b'}')

        return message_id

    def _recv(self):
        """receive the data that `send()` sent"""
        header = self._raw_sock_recv(28)
        if not (header.startswith(b'<') and header.endswith(b'>')):
            raise MySocketError("The received header {!r} does not wrap with b'<' and b'>'", b'<>', header)
        content_type, flag, content_length, message_id, verify = struct.unpack('>cBQQ8s', header[1:-1])

        content = self._raw_sock_recv(content_length + 2)

        if flag == 1:
            return b'', b'\0', 1, message_id

        if not (content.startswith(b'{') and content.endswith(b'}')):
            raise MySocketError("The received content {!r} does not wrap with b'{' and b'}'", b'{}', content)

        raw_content = self.aes.decrypt(bytearray(base64.decodebytes(content[1:-1])))
        content_verify = binascii.unhexlify(hashlib.md5(raw_content).hexdigest().encode())[-8:]
        if verify != content_verify:
            raise MySocketError("The received verify {!r} != calculated verify {!r}".format(verify, content_verify),
                                content_verify, verify)

        if message_id < self.received_msg_count:
            raise MySocketError("The just received message id {!r} < last received message id {!r} + 1".format(
                message_id, self.received_msg_count), self.received_msg_count, message_id)
        self.received_msg_count = message_id

        return raw_content, content_type, flag, message_id

    def _clean_buffer(self):
        timeout = self.get_timeout()
        self.set_blocking(True)
        try:
            self.sock.recv(1048576)
        except socket.error:
            pass
        finally:
            self.set_timeout(timeout)

    def _recv_safe(self):
        """try self._recv. if failed, clean buffer and try again"""
        while True:
            try:
                return self._recv()
            except MySocketError:
                self._clean_buffer()

    def send(self, raw_content, content_type):
        while True:
            sent_msg_id = self._send(raw_content, content_type, 0)
            self.set_timeout(4)
            try:
                _, _, flag, received_msg_id = self._recv_safe()
                if sent_msg_id == received_msg_id:
                    return
            except socket.timeout:
                pass

    def recv(self):
        while True:
            raw_content, content_type, flag, msg_id = self._recv_safe()
            if flag == 0:
                self._send(b'', b'\0', 1, msg_id)
                return raw_content, content_type

    def set_timeout(self, timeout):
        self.sock.settimeout(timeout)

    def get_timeout(self):
        return self.sock.gettimeout()

    def set_blocking(self, blocking):
        self.sock.setblocking(blocking)

    def get_blocking(self):
        return self.sock.gettimeout() == 0

    def send_bytes(self, value):
        self.send(value, b'b')

    def send_str(self, value):
        self.send(value.encode(), b's')

    def send_json(self, value):
        self.send(json.dumps(value).encode(), b'j')

    def recv_any(self):
        content, type = self.recv()
        if type == b'b':
            return content
        elif type == b's':
            return content.decode()
        elif type == b'j':
            return json.loads(content.decode())
        else:
            return content, type


class MySocketError(RuntimeError):
    def __str__(self):
        try:
            return self.args[0]
        except IndexError:
            return '<no detail>'


class AES:
    """Adapted from https://github.com/DonggeunKwon/aes/blob/master/aes/aes.py"""
    sbox = (b'c|w{\xf2ko\xc50\x01g+\xfe\xd7\xabv'
            b'\xca\x82\xc9}\xfaYG\xf0\xad\xd4\xa2\xaf\x9c\xa4r\xc0'
            b'\xb7\xfd\x93&6?\xf7\xcc4\xa5\xe5\xf1q\xd81\x15'
            b"\x04\xc7#\xc3\x18\x96\x05\x9a\x07\x12\x80\xe2\xeb'\xb2u"
            b'\t\x83,\x1a\x1bnZ\xa0R;\xd6\xb3)\xe3/\x84'
            b'S\xd1\x00\xed \xfc\xb1[j\xcb\xbe9JLX\xcf'
            b'\xd0\xef\xaa\xfbCM3\x85E\xf9\x02\x7fP<\x9f\xa8'
            b'Q\xa3@\x8f\x92\x9d8\xf5\xbc\xb6\xda!\x10\xff\xf3\xd2'
            b'\xcd\x0c\x13\xec_\x97D\x17\xc4\xa7~=d]\x19s'
            b'`\x81O\xdc"*\x90\x88F\xee\xb8\x14\xde^\x0b\xdb'
            b'\xe02:\nI\x06$\\\xc2\xd3\xacb\x91\x95\xe4y'
            b'\xe7\xc87m\x8d\xd5N\xa9lV\xf4\xeaez\xae\x08'
            b'\xbax%.\x1c\xa6\xb4\xc6\xe8\xddt\x1fK\xbd\x8b\x8a'
            b'p>\xb5fH\x03\xf6\x0ea5W\xb9\x86\xc1\x1d\x9e'
            b'\xe1\xf8\x98\x11i\xd9\x8e\x94\x9b\x1e\x87\xe9\xceU(\xdf'
            b'\x8c\xa1\x89\r\xbf\xe6BhA\x99-\x0f\xb0T\xbb\x16')
    rsbox = (b'R\tj\xd506\xa58\xbf@\xa3\x9e\x81\xf3\xd7\xfb'
             b'|\xe39\x82\x9b/\xff\x874\x8eCD\xc4\xde\xe9\xcb'
             b'T{\x942\xa6\xc2#=\xeeL\x95\x0bB\xfa\xc3N'
             b'\x08.\xa1f(\xd9$\xb2v[\xa2Im\x8b\xd1%'
             b'r\xf8\xf6d\x86h\x98\x16\xd4\xa4\\\xcc]e\xb6\x92'
             b'lpHP\xfd\xed\xb9\xda^\x15FW\xa7\x8d\x9d\x84'
             b'\x90\xd8\xab\x00\x8c\xbc\xd3\n\xf7\xe4X\x05\xb8\xb3E\x06'
             b'\xd0,\x1e\x8f\xca?\x0f\x02\xc1\xaf\xbd\x03\x01\x13\x8ak'
             b':\x91\x11AOg\xdc\xea\x97\xf2\xcf\xce\xf0\xb4\xe6s'
             b'\x96\xact"\xe7\xad5\x85\xe2\xf97\xe8\x1cu\xdfn'
             b'G\xf1\x1aq\x1d)\xc5\x89o\xb7b\x0e\xaa\x18\xbe\x1b'
             b'\xfcV>K\xc6\xd2y \x9a\xdb\xc0\xfex\xcdZ\xf4'
             b"\x1f\xdd\xa83\x88\x07\xc71\xb1\x12\x10Y'\x80\xec_"
             b'`Q\x7f\xa9\x19\xb5J\r-\xe5z\x9f\x93\xc9\x9c\xef'
             b'\xa0\xe0;M\xae*\xf5\xb0\xc8\xeb\xbb<\x83S\x99a'
             b'\x17+\x04~\xbaw\xd6&\xe1i\x14cU!\x0c}')
    rcon = b'\x01\x02\x04\x08\x10 @\x80\x1b6l\xd8\xabM\x9a/^\xbcc\xc6\x975j\xd4\xb3}\xfa\xef'

    @staticmethod
    def _MUL02(n):
        return (((n << 1) & (0xFF)) ^ (0x1B if (n & 0x80) else 0x00))

    def _MUL03(self, n):
        return self._MUL02(n) ^ n

    def __init__(self, master_key, keysize=128, operation_mode='ECB'):
        self.mk = self.__toarray(master_key)
        self.__key_expansion(self.mk)
        # will be supported
        if operation_mode != 'ECB' or keysize != 128:
            raise ValueError("Oops! It's not supported yet...")
        self.mode = operation_mode
        self.keysize = keysize

    def __toarray(self, ints):
        if isinstance(ints, (list, bytearray)) and len(ints) == 16:
            return ints
        arr = [((ints >> (8 * (15 - i))) & 0xFF) for i in range(16)]

        return arr

    def __tobyte(self, arr):
        ints = 0
        for i in range(len(arr)):
            ints += arr[15 - i] * (256 ** i)

        return ints

    def __key_expansion(self, mk, sbox=sbox, rcon=rcon):
        self.rk = mk
        for i in range(0, 10):
            self.rk.append(self.rk[(i << 4) + 0] ^ sbox[self.rk[(i << 4) + 13]] ^ rcon[i])
            self.rk.append(self.rk[(i << 4) + 1] ^ sbox[self.rk[(i << 4) + 14]])
            self.rk.append(self.rk[(i << 4) + 2] ^ sbox[self.rk[(i << 4) + 15]])
            self.rk.append(self.rk[(i << 4) + 3] ^ sbox[self.rk[(i << 4) + 12]])
            self.rk.append(self.rk[(i << 4) + 4] ^ self.rk[((i + 1) << 4) + 0])
            self.rk.append(self.rk[(i << 4) + 5] ^ self.rk[((i + 1) << 4) + 1])
            self.rk.append(self.rk[(i << 4) + 6] ^ self.rk[((i + 1) << 4) + 2])
            self.rk.append(self.rk[(i << 4) + 7] ^ self.rk[((i + 1) << 4) + 3])
            self.rk.append(self.rk[(i << 4) + 8] ^ self.rk[((i + 1) << 4) + 4])
            self.rk.append(self.rk[(i << 4) + 9] ^ self.rk[((i + 1) << 4) + 5])
            self.rk.append(self.rk[(i << 4) + 10] ^ self.rk[((i + 1) << 4) + 6])
            self.rk.append(self.rk[(i << 4) + 11] ^ self.rk[((i + 1) << 4) + 7])
            self.rk.append(self.rk[(i << 4) + 12] ^ self.rk[((i + 1) << 4) + 8])
            self.rk.append(self.rk[(i << 4) + 13] ^ self.rk[((i + 1) << 4) + 9])
            self.rk.append(self.rk[(i << 4) + 14] ^ self.rk[((i + 1) << 4) + 10])
            self.rk.append(self.rk[(i << 4) + 15] ^ self.rk[((i + 1) << 4) + 11])

    def _encrypt_block(self, pt, byte=False):
        ct = self.__toarray(pt)

        self.__addroundkey(ct, self.rk[0:16])

        for i in range(1, 10):
            self.__subbytes(ct)
            self.__shiftrows(ct)
            self.__mixcolumns(ct)
            self.__addroundkey(ct, self.rk[i * 16:(i + 1) * 16])

        self.__subbytes(ct)
        self.__shiftrows(ct)
        self.__addroundkey(ct, self.rk[(i + 1) * 16:(i + 2) * 16])

        if byte:
            return self.__tobyte(ct)

        return ct

    def _decrypt_block(self, ct, byte=False):
        pt = self.__toarray(ct)

        self.__addroundkey(pt, self.rk[10 * 16:(10 + 1) * 16])
        self.__inv_shiftrows(pt)
        self.__inv_subbytes(pt)

        for i in range(9, 0, -1):
            self.__addroundkey(pt, self.rk[i * 16:(i + 1) * 16])
            self.__inv_mixcolumns(pt)
            self.__inv_shiftrows(pt)
            self.__inv_subbytes(pt)

        self.__addroundkey(pt, self.rk[0:16])

        if byte:
            return self.__tobyte(pt)

        return pt

    @staticmethod
    def __subbytes(s, sbox=sbox):
        for i in range(16):
            s[i] = sbox[s[i]]

    @staticmethod
    def __shiftrows(s):
        s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]

    def __mixcolumns(self, s):
        _MUL02 = self._MUL02
        _MUL03 = self._MUL03
        for i in range(4):
            s0 = _MUL02(s[(i << 2) + 0]) ^ _MUL03(s[(i << 2) + 1]) ^ s[(i << 2) + 2] ^ s[(i << 2) + 3]
            s1 = _MUL02(s[(i << 2) + 1]) ^ _MUL03(s[(i << 2) + 2]) ^ s[(i << 2) + 3] ^ s[(i << 2) + 0]
            s2 = _MUL02(s[(i << 2) + 2]) ^ _MUL03(s[(i << 2) + 3]) ^ s[(i << 2) + 0] ^ s[(i << 2) + 1]
            s3 = _MUL02(s[(i << 2) + 3]) ^ _MUL03(s[(i << 2) + 0]) ^ s[(i << 2) + 1] ^ s[(i << 2) + 2]
            s[(i << 2) + 0], s[(i << 2) + 1], s[(i << 2) + 2], s[(i << 2) + 3] = s0, s1, s2, s3

    @staticmethod
    def __inv_subbytes(s, rsbox=rsbox):
        for i in range(16):
            s[i] = rsbox[s[i]]

    @staticmethod
    def __inv_shiftrows(s):
        s[1], s[5], s[9], s[13] = s[13], s[1], s[5], s[9]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        s[3], s[7], s[11], s[15] = s[7], s[11], s[15], s[3]

    def __inv_mixcolumns(self, s):
        _MUL02 = self._MUL02
        for i in range(4):
            tmp1 = _MUL02(_MUL02(s[(i << 2) + 0] ^ s[(i << 2) + 2]))
            tmp2 = _MUL02(_MUL02(s[(i << 2) + 1] ^ s[(i << 2) + 3]))
            s[(i << 2) + 0] ^= tmp1
            s[(i << 2) + 1] ^= tmp2
            s[(i << 2) + 2] ^= tmp1
            s[(i << 2) + 3] ^= tmp2
        self.__mixcolumns(s)

    @staticmethod
    def __addroundkey(s, k):
        for i in range(16):
            s[i] = s[i] ^ k[i]

    @staticmethod
    def every_bytes(n, iterable, fill=0):
        """yield every `n` elements as a bytearray"""
        iterator = iter(iterable)
        while True:
            values = bytearray(itertools.islice(iterator, n))
            if len(values) == 0:
                return
            values += bytearray(n - len(values))
            yield values

    def encrypt(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')
        if not isinstance(message, MutableSequence):
            message = bytearray(message)
        result = io.BytesIO()
        for block in self.every_bytes(16, message):
            result.write(self._encrypt_block(block))
        return result.getvalue().strip(b'\0')

    def decrypt(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')
        if not isinstance(message, MutableSequence):
            message = bytearray(message)
        result = io.BytesIO()
        for block in self.every_bytes(16, message):
            result.write(self._decrypt_block(block))
        return result.getvalue().strip(b'\0')


class DiffieHellman:
    """
    Class to represent the Diffie-Hellman key exchange protocol
    Adapted from https://github.com/DonggeunKwon/aes/blob/master/aes/aes.py
    """
    # Current minimum recommendation is 2048 bit.
    primes = {
        # 1536-bit
        5: {
            "prime": int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74'
                         '020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437'
                         '4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed'
                         'ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05'
                         '98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb'
                         '9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', base=16),
            "generator": 2
        },
        # 2048-bit
        14: {
            "prime": int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74'
                         '020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437'
                         '4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed'
                         'ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05'
                         '98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb'
                         '9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b'
                         'e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718'
                         '3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff', base=16),
            "generator": 2
        },
        # 3072-bit
        15: {
            "prime": int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74'
                         '020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437'
                         '4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed'
                         'ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05'
                         '98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb'
                         '9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b'
                         'e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718'
                         '3995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33'
                         'a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7'
                         'abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864'
                         'd87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e2'
                         '08e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff', base=16),
            "generator": 2
        },
        # 4096-bit
        16: {
            "prime": int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74'
                         '020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437'
                         '4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed'
                         'ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05'
                         '98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb'
                         '9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b'
                         'e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718'
                         '3995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33'
                         'a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7'
                         'abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864'
                         'd87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e2'
                         '08e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d7'
                         '88719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8'
                         'dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2'
                         '233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa9'
                         '93b4ea988d8fddc186ffb7dc90a6c08f4df435c934063199ffffffffffffffff', base=16),
            "generator": 2
        },
        # 6144-bit
        17: {
            "prime": int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74'
                         '020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437'
                         '4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed'
                         'ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05'
                         '98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb'
                         '9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b'
                         'e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718'
                         '3995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33'
                         'a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7'
                         'abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864'
                         'd87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e2'
                         '08e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d7'
                         '88719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8'
                         'dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2'
                         '233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa9'
                         '93b4ea988d8fddc186ffb7dc90a6c08f4df435c93402849236c3fab4d27c7026'
                         'c1d4dcb2602646dec9751e763dba37bdf8ff9406ad9e530ee5db382f413001ae'
                         'b06a53ed9027d831179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1b'
                         'db7f1447e6cc254b332051512bd7af426fb8f401378cd2bf5983ca01c64b92ec'
                         'f032ea15d1721d03f482d7ce6e74fef6d55e702f46980c82b5a84031900b1c9e'
                         '59e7c97fbec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aa'
                         'cc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58bb7c5da76'
                         'f550aa3d8a1fbff0eb19ccb1a313d55cda56c9ec2ef29632387fe8d76e3c0468'
                         '043e8f663f4860ee12bf2d5b0b7474d6e694f91e6dcc4024ffffffffffffffff', base=16),
            "generator": 2
        },
        # 8192-bit
        18: {
            "prime": int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74'
                         '020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437'
                         '4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed'
                         'ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05'
                         '98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb'
                         '9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b'
                         'e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718'
                         '3995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33'
                         'a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7'
                         'abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864'
                         'd87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e2'
                         '08e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d7'
                         '88719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8'
                         'dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2'
                         '233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa9'
                         '93b4ea988d8fddc186ffb7dc90a6c08f4df435c93402849236c3fab4d27c7026'
                         'c1d4dcb2602646dec9751e763dba37bdf8ff9406ad9e530ee5db382f413001ae'
                         'b06a53ed9027d831179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1b'
                         'db7f1447e6cc254b332051512bd7af426fb8f401378cd2bf5983ca01c64b92ec'
                         'f032ea15d1721d03f482d7ce6e74fef6d55e702f46980c82b5a84031900b1c9e'
                         '59e7c97fbec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aa'
                         'cc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58bb7c5da76'
                         'f550aa3d8a1fbff0eb19ccb1a313d55cda56c9ec2ef29632387fe8d76e3c0468'
                         '043e8f663f4860ee12bf2d5b0b7474d6e694f91e6dbe115974a3926f12fee5e4'
                         '38777cb6a932df8cd8bec4d073b931ba3bc832b68d9dd300741fa7bf8afc47ed'
                         '2576f6936ba424663aab639c5ae4f5683423b4742bf1c978238f16cbe39d652d'
                         'e3fdb8befc848ad922222e04a4037c0713eb57a81a23f0c73473fc646cea306b'
                         '4bcbc8862f8385ddfa9d4b7fa2c087e879683303ed5bdd3a062b3cf5b3a278a6'
                         '6d2a13f83f44f82ddf310ee074ab6a364597e899a0255dc164f31cc50846851d'
                         'f9ab48195ded7ea1b1d510bd7ee74d73faf36bc31ecfa268359046f4eb879f92'
                         '4009438b481c6cd7889a002ed5ee382bc9190da6fc026e479558e4475677e9aa'
                         '9e3050e2765694dfc81f56e880b96e7160c980dd98edd3dffffffffffffffff', base=16),
            "generator": 2
        }
    }

    def __init__(self, group=14):
        if group in self.primes:
            self.p = self.primes[group]["prime"]
            self.g = self.primes[group]["generator"]
        else:
            raise Exception("Group not supported")

        self.__a = random.SystemRandom().getrandbits(256)

    def get_private_key(self):
        """ Return the private key (a) """
        return self.__a

    def gen_public_key(self):
        """ Return A, A = g ^ a mod p """
        # calculate G^a mod p
        return pow(self.g, self.__a, self.p)

    def check_other_public_key(self, other_contribution):
        # check if the other public key is valid based on NIST SP800-56
        # 2 <= g^b <= p-2 and Lagrange for safe primes (g^bq)=1, q=(p-1)/2

        if 2 <= other_contribution <= self.p - 2:
            if pow(other_contribution, (self.p - 1) // 2, self.p) == 1:
                return True
        return False

    def gen_shared_key(self, other_contribution):
        """ Return g ^ ab mod p """
        # calculate the shared key G^ab mod p
        if self.check_other_public_key(other_contribution):
            self.shared_key = pow(other_contribution, self.__a, self.p)
            return hashlib.sha256(str(self.shared_key).encode()).hexdigest()
        else:
            raise Exception("Bad public key from other party")


logging.basicConfig(level=logging.INFO)


debug = True
if debug:
    def server_code():
        server = MySocket()
        server.bind(('0.0.0.0', 2020))
        server.listen()
        client, addr = server.accept()
        client.send(b'received ' + client.recv()[0], b'b')

    def client_code():
        client = MySocket()
        # client.bind(('127.0.0.1', 2021))
        client.connect(('192.168.54.41', 2020))
        client.send(b'hello server!', b'b')
        print(client.recv()[0])
