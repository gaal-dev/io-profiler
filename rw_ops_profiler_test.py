import os
import json
import codecs
import io
import pytest

from telemetry.rw_ops_profiler import file, wrap_file_open
wrap_file_open()


def test_rw_ops_profiler_open(tmpdir):
    filepath = str(tmpdir.join("sample.txt"))
    with open(filepath, "w+") as fobj:
        assert type(fobj), file


def test_rw_ops_profiler_file(tmpdir):
    filepath = str(tmpdir.join("sample.txt"))
    fobj = file(filepath, "w+")
    assert type(fobj), file


def test_rw_ops_profiler_mode(tmpdir):
    filepath = str(tmpdir.join("sample.txt"))
    with open(filepath, "w+") as fobj:
        assert fobj.mode, "w+"


def test_rw_ops_profiler_name(tmpdir):
    filepath = str(tmpdir.join("sample.txt"))
    with open(filepath, "w+") as fobj:
        assert fobj.name, filepath


def test_rw_ops_profiler_closed(tmpdir):
    filepath = str(tmpdir.join("sample.txt"))
    with open(filepath, "w+") as fobj:
        assert fobj.closed is False
    assert fobj.closed is True


def test_rw_ops_profiler_read_write(tmpdir):
    filepath = str(tmpdir.join("sample.txt"))
    with open(filepath, "w+") as fobj:
        fobj.write("Twinkle, twinkle, little star")
    with open(filepath, "r") as fobj:
        text = fobj.read()
    assert text, "Twinkle, twinkle, little star"


def test_rw_ops_profiler_readline(tmpdir):
    filepath = str(tmpdir.join("sample.txt"))
    with open(filepath, "w+") as fobj:
        fobj.write("How I wonder what you are")
    with open(filepath, "r") as fobj:
        text = fobj.readline()
    assert text, "How I wonder what you are"


def test_rw_ops_profiler_readlines(tmpdir):
    filepath = str(tmpdir.join("sample.txt"))
    with open(filepath, "w+") as fobj:
        fobj.write("Five little monkeys jumping on the bed...")
    with open(filepath, "r") as fobj:
        text = fobj.readlines()
    assert text, ["Five little monkeys jumping on the bed..."]


def test_rw_ops_profiler_writelines(tmpdir):
    filepath = str(tmpdir.join("sample.txt"))
    with open(filepath, "w+") as fobj:
        fobj.writelines(["One fell down and bumped his head"])
    with open(filepath, "r") as fobj:
        text = fobj.readlines()
    assert text, ["One fell down and bumped his head"]


def test_rw_ops_profiler_xreadlines(tmpdir):
    filepath = str(tmpdir.join("sample.txt"))
    with open(filepath, "w+") as fobj:
        fobj.writelines(["Mama called the doctor and the doctor said"])
    with open(filepath, "r") as fobj:
        text = [line for line in fobj.xreadlines()]
    assert text, ["Mama called the doctor and the doctor said"]


def test_rw_ops_profiler_iter(tmpdir):
    filepath = str(tmpdir.join("sample.txt"))
    with open(filepath, "w+") as fobj:
        fobj.writelines(["No more monkeys jumping on the bed!"])
    with open(filepath, "r") as fobj:
        text = [line for line in fobj]
    assert text, ["No more monkeys jumping on the bed!"]


def test_rw_ops_profiler_codecs_read_write(tmpdir, monkeypatch):
    text = u"London Bridge is falling down,\nFalling down, falling down.\nLondon Bridge is falling down,\nMy fair lady."
    filepath = str(tmpdir.join("sample.txt"))
    with codecs.open(filepath, "w+", encoding="utf8") as fobj:
        fobj.write(text)
    with codecs.open(filepath, "r", encoding="utf8") as fobj:
        res = fobj.read()
    assert res, text


def test_rw_ops_profiler_io_read_write(tmpdir, monkeypatch):
    text = u"London Bridge is falling down,\nFalling down, falling down.\nLondon Bridge is falling down,\nMy fair lady."
    filepath = str(tmpdir.join("sample.txt"))
    with io.open(filepath, "w+", encoding="utf8") as fobj:
        fobj.write(text)
    with io.open(filepath, "r", encoding="utf8") as fobj:
        res = fobj.read()
    assert res, text


TALE_TEXT = u"""The North Wind and The Sun

The North Wind boasted of great strength. The Sun argued that there was great power in gentleness.
"We shall have a contest," said the Sun.
Far below, a man traveled a winding road. He was wearing a warm winter coat.
"As a test of strength," said the Sun, "Let us see which of us can take the coat off of that man."
"It will be quite simple for me to force him to remove his coat," bragged the Wind.
The Wind blew so hard, the birds clung to the trees. The world was filled with dust and leaves. But the harder the wind blew down the road, the tighter the shivering man clung to his coat.
Then, the Sun came out from behind a cloud. Sun warmed the air and the frosty ground. The man on the road unbuttoned his coat.
The sun grew slowly brighter and brighter.
Soon the man felt so hot, he took off his coat and sat down in a shady spot.
"How did you do that?" said the Wind.
"It was easy," said the Sun, "I lit the day. Through gentleness I got my way."""


@pytest.mark.parametrize("open_function", [
    open,
    io.open,
    codecs.open
])
def test_rw_ops_profiler_check_sum(tmpdir, monkeypatch, open_function):
    messages = []
    filepath = str(tmpdir.join("sample.txt"))

    class DummyLogger(object):
        def info(self, msg):
            msg = json.loads(msg)
            if msg["file_path"] == filepath:
                messages.append(msg)

    import telemetry.rw_ops_profiler
    monkeypatch.setattr(telemetry.rw_ops_profiler, "logger", DummyLogger())

    chunk_num = len(TALE_TEXT) / 10 + 1

    with open_function(filepath, "w+") as fobj:
        for i in range(chunk_num):
            chunk = TALE_TEXT[(i * 10) : (i + 1) * 10]
            if chunk:
                fobj.write(chunk)
    with open_function(filepath, "r") as fobj:
        res = fobj.read()
    assert res, TALE_TEXT

    messages = [{"file_path": message["file_path"], "file_op": message["file_op"],
                 "num_bytes": message["num_bytes"], "pid": message["pid"]}
                for message in messages if message["num_bytes"]]  # remove stack and empty num_bytes fields

    res = {}
    for message in messages:
        key = (message["file_path"], message["file_op"], message["pid"])
        if key not in res:
            res[key] = 0
        res[key] += message["num_bytes"]

    expected = {(filepath, "read", os.getpid()): len(TALE_TEXT),
                (filepath, "write", os.getpid()): len(TALE_TEXT)}

    assert res, expected
