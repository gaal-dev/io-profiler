import argparse
import io
import json
import sys
from collections import namedtuple, OrderedDict


class RWOpsCompressor(object):
    LogRecord = namedtuple("LogRecord", "date, time, app, level, msg")

    @staticmethod
    def __to_tuple(stack):
        return tuple(tuple(line) for line in stack)

    def compress_log(self, input_log_path, output_log_path, verbose=False):
        if verbose:
            sys.stderr.write("Start compressing: %s\n" % input_log_path)

        stack_traces = {}
        with io.open(input_log_path, "r", encoding="utf-8") as logFile:
            for num, line in enumerate(logFile):
                if verbose:
                    sys.stderr.write("%d: %s" % (num, line))

                lg = RWOpsCompressor.LogRecord(*line.strip("\n").split(" ", 4))
                if lg.app != "rwops_telemetry":
                    continue

                try:
                    in_msg = json.loads(lg.msg)
                except ValueError as ex:
                    sys.stderr.write("Warning: %d line is corrupted" % num)
                    continue

                stack_trace_key = (lg.app, lg.level, in_msg["file_path"], in_msg["file_op"], in_msg["pid"],
                                   RWOpsCompressor.__to_tuple(in_msg["stack"]))

                if stack_trace_key not in stack_traces:
                    stack_traces[stack_trace_key] = OrderedDict()
                    st_dict = stack_traces[stack_trace_key]
                    st_dict["srv"] = OrderedDict()
                    srv = st_dict["srv"]
                    srv["date"] = lg.date
                    srv["time"] = lg.time
                    srv["app"] = lg.app
                    srv["level"] = lg.level
                    st_dict["msg"] = OrderedDict()
                    out_msg = st_dict["msg"]
                    out_msg["file_path"] = in_msg["file_path"]
                    out_msg["file_op"] = in_msg["file_op"]
                    out_msg["pos"] = -1  # not actual position
                    out_msg["num_bytes"] = 0
                    out_msg["counter"] = 0
                    out_msg["pid"] = in_msg["pid"]
                    out_msg["stack"] = in_msg["stack"]

                st_dict_msg = stack_traces[stack_trace_key]["msg"]
                st_dict_msg["num_bytes"] += in_msg["num_bytes"]
                st_dict_msg["counter"] += 1

        if verbose:
            sys.stderr.write("End compressing: %s\n" % input_log_path)
            sys.stderr.write("Start writing: %s\n" % output_log_path)

        with io.open(output_log_path, "w+", encoding="utf-8") as logFile:
            stack_traces = sorted(stack_traces.items(),
                                  key=lambda item: (item[1]["srv"]["date"], item[1]["srv"]["time"],
                                                    item[1]["msg"]["num_bytes"], item[1]["msg"]["file_op"]))
            for num, (key, value) in enumerate(stack_traces):
                line = "%s %s %s %s %s\n" % (value["srv"]["date"], value["srv"]["time"], key[0], key[1],
                                             json.dumps({k: v for k, v in value["msg"].items()}))
                if verbose:
                    sys.stderr.write("%d: %s" % (num, line))

                logFile.write(line)

        if verbose:
            sys.stderr.write("End writing: %s\n" % output_log_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read-write operation compressor")
    parser.add_argument("-i", "--input-log-path", help="log path", required=True)
    parser.add_argument("-o", "--output-log-path", help="log path", required=True)
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
    args = parser.parse_args()

    compressor = RWOpsCompressor()
    compressor.compress_log(args.input_log_path, args.output_log_path, args.verbose)
