import pickle
import struct
import os
import json
import datetime
import argparse
import SocketServer
import logging
import logging.handlers

LOGGING_SERVER = "localhost"
LOGGING_PORT = logging.handlers.DEFAULT_TCP_LOGGING_PORT


class LogRecordStreamHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        while True:
            chunk = self.connection.recv(4)
            if len(chunk) < 4:
                break
            slen = struct.unpack(">L", chunk)[0]
            chunks = [self.connection.recv(slen)]
            chunks_len = len(chunks[0])
            while chunks_len < slen:
                chunks.append(self.connection.recv(slen - chunks_len))
                chunks_len += len(chunks[-1])
            obj = self.unPickle("".join(chunks))
            record = logging.makeLogRecord(obj)
            self.handleLogRecord(record)

    def unPickle(self, data):
        return pickle.loads(data)

    def handleLogRecord(self, record):
        if record.name != "rwops_telemetry":
            return

        if self.server.logname is not None:
            name = self.server.logname
        else:
            name = record.name

        logger = logging.getLogger(name)
        if self.__checkRecord(record):
            logger.handle(record)

    def __checkRecord(self, record):
        content = json.loads(record.msg)
        return content["file_path"] != self.server.logpath


class LogRecordSocketReceiver(SocketServer.ThreadingTCPServer):
    """
    Simple TCP socket-based logging receiver suitable for testing.
    """

    allow_reuse_address = True

    def __init__(self, host=LOGGING_SERVER, port=LOGGING_PORT, handler=LogRecordStreamHandler, logpath=None):
        SocketServer.ThreadingTCPServer.__init__(self, (host, port), handler)
        self.abort = 0
        self.timeout = 1
        self.logname = None
        self.logpath = logpath

    def serve_until_stopped(self):
        import select
        abort = 0
        while not abort:
            rd, wr, ex = select.select([self.socket.fileno()], [], [], self.timeout)
            if rd:
                self.handle_request()
            abort = self.abort


def main(log_path=None, no_console=False):
    rootLogger = logging.getLogger("")
    rootLogger.setLevel(logging.DEBUG)

    formatter = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")

    if not no_console:
        consoleHandler = logging.StreamHandler()
        consoleHandler.setFormatter(formatter)
        rootLogger.addHandler(consoleHandler)
    else:
        consoleHandler = None

    if log_path is not None:
        if os.path.exists(log_path):
            mod_timestamp = datetime.datetime.fromtimestamp(os.path.getmtime(log_path))
            os.rename(log_path, log_path + "." + mod_timestamp.strftime("%m%d%Y%H%M%S"))

        fileHandler = logging.FileHandler(log_path)
        fileHandler.setFormatter(formatter)
        rootLogger.addHandler(fileHandler)
    else:
        fileHandler = None

    tcpServer = None
    try:
        tcpServer = LogRecordSocketReceiver()
        tcpServer.logpath = log_path
        print("About to start TCP server...")
        tcpServer.serve_until_stopped()
    except KeyboardInterrupt:
        if tcpServer:
            tcpServer.abort = 1
        if consoleHandler:
            rootLogger.removeHandler(consoleHandler)
        if fileHandler:
            rootLogger.removeHandler(fileHandler)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read-write operation analyzer")
    parser.add_argument("-l", "--log-path", help="log path")
    parser.add_argument("-n", "--no-console", action="store_true", help="no console logging")
    args = parser.parse_args()
    main(args.log_path, args.no_console)
