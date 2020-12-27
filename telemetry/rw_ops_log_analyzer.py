import argparse
import io
import json
import sys
from collections import namedtuple, OrderedDict
from graphviz import Digraph, ENGINES, FORMATS


class RWOpsLogAnalyzer(object):  # TODO: simplify diagrams
    LogRecord = namedtuple("LogRecord", "date, time, app, level, msg")
    StackRecord = namedtuple("StackRecord", "filename, line_number, function_name, text")

    INTERMEDIATE_NODE = {"color": "cyan", "fontcolor": "black", "style": "filled", "shape": "box"}
    START_NODE = {"color": "magenta", "fontcolor": "black", "style": "filled", "shape": "box"}
    END_NODE = {"color": "yellow", "fontcolor": "black", "style": "filled", "shape": "box"}
    TABLE_NODE = {"color": "white", "fontcolor": "black", "style": "filled", "fontsize": "25"}
    EDGE_NECESSARY = {"penwidth": "5.0", "color": "grey"}
    EDGE_UNNECESSARY = {"penwidth": "2.0", "color": "lightgrey"}

    def __init__(self):
        self.__reset()

    def __reset(self):
        self.data_flows = {}
        self.gen_flow_id = 0
        self.file_summary = {}
        self.tree = OrderedDict()
        self.node_attrs = {}
        self.graph = None

    def build_graph(self, log_path, report_path, engine="dot", _format="svg",
                    included_paths=None, excluded_paths=None, excluded_stack_lines=None,
                    ignore_path_case=False, full_stack=False, verbose=False):
        self.__reset()

        if ignore_path_case:
            included_paths = tuple(path.lower() for path in included_paths)
            excluded_paths = tuple(path.lower() for path in excluded_paths)
            excluded_stack_lines = tuple([excluded_filename.lower(), excluded_line_number]
                                         for excluded_filename, excluded_line_number in excluded_stack_lines)

        self.graph = Digraph("Read-write operations", filename=report_path, engine=engine, format=_format)
        self.graph.attr(splines="ortho")

        if verbose:
            sys.stderr.write("Start processing: %s\n" % log_path)

        skipped = set()
        with io.open(log_path, "r", encoding="utf-8") as logFile:
            for num, line in enumerate(logFile):
                if verbose:
                    sys.stderr.write("%d: %s" % (num, line))

                lg = RWOpsLogAnalyzer.LogRecord(*line.strip("\n").split(" ", 4))
                if lg.app != "rwops_telemetry":
                    continue

                try:
                    msg = json.loads(lg.msg)
                except ValueError as ex:
                    sys.stderr.write("Warning: %d line is corrupted\n" % num)
                    continue

                if msg["file_path"].endswith((".py", ".egg-info", "PKG-INFO")):
                    continue
                else:
                    file_path = msg["file_path"]
                    if ignore_path_case:
                        file_path = file_path.lower()
                        if (included_paths and not file_path.startswith(included_paths)) or \
                                (excluded_paths and file_path.startswith(excluded_paths)):
                            skipped.add(msg["file_path"])
                            continue

                file_path, file_op, num_bytes, counter = \
                    RWOpsLogAnalyzer.__escape_text(msg["file_path"]), \
                    msg["file_op"], msg["num_bytes"], msg.get("counter", 1)
                self.__update_file_summary(file_path, file_op, num_bytes, counter)

                stack_keys = self.__get_stack_keys(msg["stack"], file_path, excluded_stack_lines, ignore_path_case)

                sub_tree, sub_node_attrs = self.__build_stack_subtree(stack_keys)
                self.node_attrs.update(sub_node_attrs)

                if sub_tree:
                    self.__update_stack_tree(sub_tree, file_path, file_op, num_bytes, counter, stack_keys, full_stack)

        if verbose:
            sys.stderr.write("Skipped:\n" + "\n".join(sorted(skipped)) + "\n")
            sys.stderr.write("End processing: %s\n" % log_path)

        self.__fill_graph(verbose)

        self.graph.view()

    @staticmethod
    def __escape_text(text):
        # reserved characters are replaced: u+ff1a - full width colon / u+2215 - division slash
        return text.replace(u"\\", u"\uff3c").replace(u":", u"\uff1a") if text else ""

    @staticmethod
    def __unescape_text(text):
        # reserved characters are replaced: u+ff1a - full width colon / u+2215 - division slash
        return text.replace(u"\uff3c", u"\\").replace(u"\uff1a", u":") if text else ""

    def __update_file_summary(self, file_path, file_op, num_bytes, counter):
        if file_path not in self.file_summary:
            self.file_summary[file_path] = {"read": {"bytes": 0, "counter": 0}, "write": {"bytes": 0, "counter": 0}}

        file_summary_file_path = self.file_summary[file_path]
        file_summary_file_path[file_op]["bytes"] += num_bytes
        file_summary_file_path[file_op]["counter"] += counter

    def __get_stack_keys(self, stack, endpoint, excluded_stack_lines, ignore_path_case=False):
        def is_stack_line_excluded(filename, line_number):
            if not excluded_stack_lines:
                return False

            if ignore_path_case:
                filename = filename.lower()

            for excluded_filename, excluded_line_number in excluded_stack_lines:
                if (filename == excluded_filename and line_number == excluded_line_number) or \
                        (filename.startswith(excluded_filename) and excluded_line_number < 0):
                    return True
            return False

        stack_keys = []
        for rec in stack:
            sr = RWOpsLogAnalyzer.StackRecord(*rec)
            if is_stack_line_excluded(sr.filename, sr.line_number):
                continue
            # \l left \r right
            stack_key = (u"%s, %s\l%s\uff1a%s\l" % (RWOpsLogAnalyzer.__escape_text(sr.filename), sr.line_number,
                                               sr.function_name, RWOpsLogAnalyzer.__escape_text(sr.text) if sr.text else ""))
            stack_keys.append(stack_key)
        stack_keys.append(endpoint)
        return stack_keys

    def __build_stack_subtree(self, stack_keys):
        sub_node_attrs = {}
        hi = len(stack_keys) - 1
        prev = None
        sub_tree = {}
        for i, key in enumerate(stack_keys):
            sub_node_attrs[key] = {0: RWOpsLogAnalyzer.START_NODE,
                                   hi: RWOpsLogAnalyzer.END_NODE}\
                .get(i, RWOpsLogAnalyzer.INTERMEDIATE_NODE)

            if key not in sub_tree:
                sub_tree[key] = []
            if prev:
                sub_tree[prev].append(key)
            prev = key
        return sub_tree, sub_node_attrs

    def __check_key(self, key):
        if key not in self.tree:
            self.tree[key] = OrderedDict()

    def __check_prev_key(self, prev, key, file_op, num_bytes, counter, flow_id):
        if prev:
            tree_prev = self.tree[prev]
            if key not in tree_prev:
                tree_prev[key] = {"data_flows": OrderedDict()}

            tree_prev_key = tree_prev[key]
            if file_op:
                if file_op not in tree_prev_key:
                    tree_prev_key[file_op] = {"bytes": 0, "counter": 0}

                tree_prev_key_file_op = tree_prev_key[file_op]
                tree_prev_key_file_op["bytes"] += num_bytes
                tree_prev_key_file_op["counter"] += counter

            tree_prev_key_data_flows = tree_prev_key["data_flows"]
            if flow_id not in tree_prev_key_data_flows:
                tree_prev_key_data_flows[flow_id] = {}

            if file_op:
                tree_prev_key_data_flows_flow_id = tree_prev_key_data_flows[flow_id]
                if file_op not in tree_prev_key_data_flows_flow_id:
                    tree_prev_key_data_flows_flow_id[file_op] = {"bytes": 0, "counter": 0}

                tree_prev_key_data_flows_flow_id_file_op = tree_prev_key_data_flows_flow_id[file_op]
                tree_prev_key_data_flows_flow_id_file_op["bytes"] += num_bytes
                tree_prev_key_data_flows_flow_id_file_op["counter"] += counter

    def __update_stack_tree(self, sub_tree, endpoint, file_op, num_bytes, counter, stack_keys, full_stack):
        entrypoint = stack_keys[0]
        if entrypoint not in self.data_flows:
            self.gen_flow_id += 1
            self.data_flows[entrypoint] = self.gen_flow_id
        flow_id = self.data_flows[entrypoint]

        path = RWOpsLogAnalyzer.__find_path(sub_tree, entrypoint, endpoint)

        prev = None
        for key in path:
            self.__check_key(key)
            self.__check_prev_key(prev, key, file_op, num_bytes, counter, flow_id)
            prev = key

        if full_stack:
            prev = None
            for key in stack_keys:
                self.__check_key(key)
                self.__check_prev_key(prev, key, "", 0, 0, flow_id)
                prev = key

    @staticmethod
    def __get_flow_summary_with_bytes(flows, file_op):
        return "\l".join(["flow {} {} ({} times) - {:,} bytes".format(flow_id, file_op,
                                                                    flow_num_bytes[file_op]["counter"],
                                                                    flow_num_bytes[file_op]["bytes"])
                          for flow_id, flow_num_bytes in flows["data_flows"].items() if file_op in flow_num_bytes])

    @staticmethod
    def __get_flow_summary_without_bytes(flows):
        return "\l".join(["flow %d" % flow_id for flow_id in flows["data_flows"].keys()])

    @staticmethod
    def __get_total_summary(flows, file_op):
        return "total {} ({} times) - {:,} bytes\l{}\l"\
            .format(file_op, flows[file_op]["counter"], flows[file_op]["bytes"],
                    RWOpsLogAnalyzer.__get_flow_summary_with_bytes(flows, file_op))

    @staticmethod
    def __get_file_summary(num_bytes):
        return ("read ({} times) - {:,} bytes"
                .format(num_bytes["read"]["counter"], num_bytes["read"]["bytes"])
                if num_bytes["read"]["bytes"] else "") + \
               (", " if num_bytes["read"]["bytes"] and num_bytes["write"]["bytes"] else "") + \
               ("write ({} times) - {:,} bytes"
                .format(num_bytes["write"]["counter"], num_bytes["write"]["bytes"])
                if num_bytes["write"]["bytes"] else "") \
            if num_bytes["read"]["bytes"] or num_bytes["write"]["bytes"] else "-"

    def __fill_graph(self, verbose=False):
        sorted_files = sorted(self.file_summary.items(),
                              key=lambda item: (sys.maxint - max(item[1]["write"]["bytes"], item[1]["read"]["bytes"]),
                                                item[0]))
        text = "\l".join("%s: %s" % (file_path, RWOpsLogAnalyzer.__get_file_summary(num_bytes))
                        for file_path, num_bytes in sorted_files) + "\l"
        self.graph.node("files", text, shape="box", **RWOpsLogAnalyzer.TABLE_NODE)

        if verbose:
            sys.stderr.write("Start creating: %s\n" % self.graph.filepath)

        src_len = len(self.tree)
        for src_num, (src, dst_edges) in enumerate(self.tree.items(), start=1):
            if verbose:
                sys.stderr.write("%d/%d source node: %s\n" % (src_num, src_len, src))

            dst_len = len(dst_edges)
            for dst_num, (dst, dst_flows) in enumerate(dst_edges.items(), start=1):
                if verbose:
                    sys.stderr.write("%d/%d destination node: %s\n" % (dst_num, dst_len, dst))

                if src in self.node_attrs:
                    self.graph.node(src, **self.node_attrs[src])
                    del self.node_attrs[src]

                if dst in self.node_attrs:
                    self.graph.node(dst, **self.node_attrs[dst])
                    del self.node_attrs[dst]

                label = RWOpsLogAnalyzer.__get_total_summary(dst_flows, "read") if "read" in dst_flows else ""
                if "write" in dst_flows:
                    label += RWOpsLogAnalyzer.__get_total_summary(dst_flows, "write")

                edge_style = RWOpsLogAnalyzer.EDGE_NECESSARY if label else RWOpsLogAnalyzer.EDGE_UNNECESSARY

                if not label:
                    label = RWOpsLogAnalyzer.__get_flow_summary_without_bytes(dst_flows)

                self.graph.edge(src, dst, label=label, **edge_style)

        if verbose:
            sys.stderr.write("End creating: %s\n" % self.graph.filepath)
            sys.stderr.write("Files:\n" + RWOpsLogAnalyzer.__unescape_text(text.replace("\l", "\n")))

    @staticmethod
    def __find_path(tree, start, end):
        visited = {start}
        queue = [start]
        parents = {}

        while queue:
            cur_item = queue.pop(0)
            if cur_item == end:
                return RWOpsLogAnalyzer.__get_path(start, end, parents)

            for item in tree[cur_item]:
                if item not in visited:
                    visited.add(item)
                    queue.append(item)
                    parents[item] = cur_item

        return []

    @staticmethod
    def __get_path(start, end, parents):
        path = []
        cur = end
        while cur != start:
            path.append(cur)
            cur = parents[cur]
        path.append(start)
        return path[::-1]


def __excluded_stack(excluded_stack_line):
    excluded_stack_line = excluded_stack_line.rsplit(",", 1)
    if len(excluded_stack_line) > 2:
        raise argparse.ArgumentError("Wrong format of an excluded stack line")
    if len(excluded_stack_line) > 1:
        excluded_stack_line[1] = int(excluded_stack_line[1])
    else:
        excluded_stack_line += [-1]
    return excluded_stack_line


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Logging monitoring analyzer")
    parser.add_argument("-l", "--log-path", help="log path", required=True)
    parser.add_argument("-r", "--report-path", help="report path", required=True)
    parser.add_argument("-g", "--engine", help="graphviz engine", choices=ENGINES, default="dot")
    parser.add_argument("-o", "--format", help="graphviz format", choices=FORMATS, default="pdf")
    parser.add_argument("-i", "--included-paths", nargs="+", help="included paths")
    parser.add_argument("-e", "--excluded-paths", nargs="+", help="excluded paths")
    parser.add_argument("-s", "--excluded-stack", nargs="+", help="excluded stack lines (filename,line_number)",
                        type=__excluded_stack)
    parser.add_argument("-c", "--ignore-path-case", action="store_true", help="ignore path case")
    parser.add_argument("-f", "--full-stack", action="store_true", help="show all stack lines")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
    args = parser.parse_args()

    analyzer = RWOpsLogAnalyzer()
    analyzer.build_graph(args.log_path, args.report_path, args.engine, args.format,
                         tuple(args.included_paths if args.included_paths else []),
                         tuple(args.excluded_paths if args.excluded_paths else []),
                         args.excluded_stack, args.ignore_path_case, args.full_stack, args.verbose)
