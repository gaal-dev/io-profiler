import __builtin__
import os
import json
import threading
import io
import traceback
import logging.handlers
from collections import OrderedDict

LOGGING_SERVER = "localhost"
LOGGING_PORT = logging.handlers.DEFAULT_TCP_LOGGING_PORT

rootLogger = logging.getLogger("")
rootLogger.setLevel(logging.DEBUG)
socketHandler = logging.handlers.SocketHandler(LOGGING_SERVER, LOGGING_PORT)

rootLogger.addHandler(socketHandler)

logger = logging.getLogger("rwops_telemetry")

builtin_file_constructor = __builtin__.file
builtin_open_function = __builtin__.open
io_open = io.open

module_name, _ = os.path.splitext(__file__)
this_module = (module_name + ".py", module_name + ".pyc")  # .py and .pyc


class file(builtin_file_constructor):
    __send_events = set()

    def __new__(cls, name, mode, buffering=-1):
        item = (threading.current_thread().ident, name)
        if item in file.__send_events:
            instance = builtin_file_constructor.__new__(builtin_file_constructor, name, mode, buffering)
        else:
            instance = builtin_file_constructor.__new__(cls, name, mode, buffering)

        # A file constructor has to be called explicitly if __new__ returns an instance differs from cls class
        instance.__init__(name, mode, buffering)
        return instance

    @staticmethod
    def open(name, mode="r", buffering=-1):
        return file(name, mode, buffering)

    def __init__(self, name, mode="r", buffering=-1):
        super(file, self).__init__(name, mode, buffering)

    def __iter__(self):
        # super(file, self).__iter__ is a recursive call of the __iter__ function
        while True:
            p_str = self.readline()
            if not p_str:
                break
            yield p_str

    def xreadlines(self):
        return self

    def read(self, size=-1):
        cfp = self.tell()
        p_str = super(file, self).read(size)
        self.__send_event("read", self.name, cfp, self.tell() - cfp)
        return p_str

    def readline(self, size=-1):
        cfp = self.tell()
        p_str = super(file, self).readline(size)
        self.__send_event("read", self.name, cfp, self.tell() - cfp)
        return p_str

    def readlines(self, size=-1):
        cfp = self.tell()
        sequence_of_strings = super(file, self).readlines(size)
        self.__send_event("read", self.name, cfp, self.tell() - cfp)
        return sequence_of_strings

    def write(self, p_str):
        cfp = self.tell()
        super(file, self).write(p_str)
        self.__send_event("write", self.name, cfp, self.tell() - cfp)

    def writelines(self, sequence_of_strings):
        cfp = self.tell()
        super(file, self).writelines(sequence_of_strings)
        self.__send_event("write", self.name, cfp, self.tell() - cfp)

    @staticmethod
    def __send_event(file_op, name, pos, num_bytes):
        item = (threading.current_thread().ident, name)
        try:
            file.__send_events.add(item)
            stack = traceback.extract_stack()
        finally:
            file.__send_events.remove(item)

        # remove stack lines about this monitoring module
        stack = [line for line in stack if line[0] not in this_module]

        msg = OrderedDict()
        msg["file_path"] = name
        msg["file_op"] = file_op
        msg["pos"] = pos
        msg["num_bytes"] = num_bytes
        msg["pid"]= os.getpid()
        msg["stack"] = stack

        logger.info(json.dumps(msg))


class stream_wrapper(object):
    def __init__(self, stream):
        self.__stream = stream

    def __getattr__(self, name):
        return getattr(self.__stream, name)

    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        self.__stream.close()

    def __iter__(self):
        while True:
            # IOError: telling position disabled by next() call
            p_str = self.readline()
            if not p_str:
                break
            yield p_str

    def read(self, size=-1):
        bfp = self.__stream.tell()
        p_str = self.__stream.read(size)
        efp = self.__stream.tell()
        self.__send_event("read", self.__stream.name, bfp, efp - bfp)
        return p_str

    def readline(self, size=-1):
        bfp = self.__stream.tell()
        p_str = self.__stream.readline(size)
        efp = self.__stream.tell()
        self.__send_event("read", self.__stream.name, bfp, efp - bfp)
        return p_str

    def readlines(self, size=-1):
        bfp = self.__stream.tell()
        sequence_of_strings = self.__stream.readlines(size)
        efp = self.__stream.tell()
        self.__send_event("read", self.__stream.name, bfp, efp - bfp)
        return sequence_of_strings

    def write(self, p_str):
        bfp = self.__stream.tell()
        self.__stream.write(p_str)
        efp = self.__stream.tell()
        self.__send_event("write", self.__stream.name, bfp, efp - bfp)

    def writelines(self, sequence_of_strings):
        bfp = self.__stream.tell()
        self.__stream.writelines(sequence_of_strings)
        efp = self.__stream.tell()
        self.__send_event("write", self.__stream.name, bfp, efp - bfp)

    @staticmethod
    def __send_event(file_op, name, pos, num_bytes):
        stack = traceback.extract_stack()

        # remove stack lines about this monitoring module
        stack = [line for line in stack if line[0] not in this_module]

        msg = OrderedDict()
        msg["file_path"] = name
        msg["file_op"] = file_op
        msg["pos"] = pos
        msg["num_bytes"] = num_bytes
        msg["pid"]= os.getpid()
        msg["stack"] = stack

        logger.info(json.dumps(msg))


class TextIOWrapper(stream_wrapper):  # TODO: io.TextIOWrapper must be a base class but a file is closed
    @staticmethod
    def io_open(file, mode="r", buffering=-1, encoding=None, errors=None, newline=None, closefd=True):
        instance = io_open(file, mode, buffering, encoding, errors, newline, closefd)
        return TextIOWrapper(instance)


def wrap_file_open():
    __builtin__.file = file
    __builtin__.open = file.open
    io.open = TextIOWrapper.io_open


def unwrap_file_open():
    __builtin__.file = builtin_file_constructor
    __builtin__.open = builtin_open_function
    io.open = io_open
