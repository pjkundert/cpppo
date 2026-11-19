"""Execute the README.org Python source blocks and compare their stdout."""

from contextlib import contextmanager
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import time


BLOCK = re.compile(
    r"^(?:[ \t]*#\+name:[ \t]*(\S+)[ \t]*\n)?"
    r"[ \t]*#\+begin_src[ \t]+python\b([^\n]*)\n"
    r"(.*?)^[ \t]*#\+end_src[ \t]*$",
    re.IGNORECASE | re.MULTILINE | re.DOTALL,
)
RESULT = re.compile(
    r"^[ \t]*#\+results:[ \t]*(\S+)[ \t]*\n((?:[ \t]*:[^\n]*\n)*)",
    re.IGNORECASE | re.MULTILINE,
)


def python_code(source):
    return [sys.executable, '-I', '-u', '-c', source]


def check_output(name, actual, expected):
    if actual.splitlines() != expected:
        raise AssertionError("{} stdout\nexpected: {!r}\nactual: {!r}".format(
            name, expected, actual.splitlines()))


@contextmanager
def server(command, port, banner=None):
    address = ('127.0.0.1', port)
    with socket.socket() as bind_check:
        bind_check.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_check.bind(address)
    with tempfile.TemporaryFile() as stdout:
        process = subprocess.Popen(command, stdout=stdout)
        try:
            deadline = time.monotonic() + 10
            while process.poll() is None and time.monotonic() < deadline:
                if banner is not None:
                    output = os.pread(stdout.fileno(), 65536, 0)
                    if output.endswith(b'\n'):
                        check_output('class1-adapter', output.decode('utf-8'), banner)
                        break
                else:
                    try:
                        with socket.create_connection(address, timeout=.2):
                            break
                    except OSError:
                        pass
                time.sleep(.05)
            else:
                stdout.seek(0)
                raise RuntimeError("Server on port {} failed to start: {!r}".format(port, stdout.read()))
            yield
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def run_block(name, command, expected):
    result = subprocess.run(command, stdout=subprocess.PIPE, text=True, check=True, timeout=20)
    check_output(name, result.stdout, expected)
    print("{}: passed".format(name), flush=True)


def main(readme):
    doc = readme.read_text(encoding='utf-8')
    expected = {
        name: [line.lstrip()[1:].removeprefix(' ') for line in results.splitlines()]
        for name, results in RESULT.findall(doc)
    }
    blocks = {}
    for name, headers, source in BLOCK.findall(doc):
        if not name or name in blocks or name not in expected:
            raise ValueError("Every Python block needs a unique name and a matching RESULTS entry: {!r}".format(name))
        blocks[name] = (headers, textwrap.dedent(source))

    _, source = blocks.pop('class1-adapter')
    with server(python_code(source), 44818, expected['class1-adapter']):
        print("class1-adapter: passed", flush=True)
        _, source = blocks.pop('class1-scanner')
        run_block('class1-scanner', python_code(source), expected['class1-scanner'])

    _, source = blocks.pop('modbus-poller')
    with server([sys.executable, '-I', '-m', 'cpppo.bin.modbus_sim',
                 '-a', '127.0.0.1:1502', '40001-40100=99'], 1502):
        run_block('modbus-poller', python_code(source), expected['modbus-poller'])

    sessions = {}
    for name, (headers, source) in blocks.items():
        session = re.search(r'\s:session\s+(\S+)', headers)
        if session:
            previous = sessions.get(session[1], '')
            sessions[session[1]] = previous + '\n' + source
            if previous:
                # Restore earlier definitions without reprinting their output.
                source = ("import contextlib as _contextlib, io as _io\n"
                          "with _contextlib.redirect_stdout(_io.StringIO()):\n"
                          "    exec({!r})\n".format(previous)) + source
        run_block(name, python_code(source), expected[name])


if __name__ == '__main__':
    main(Path(sys.argv[1]))
