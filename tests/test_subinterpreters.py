import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

_interpreters = pytest.importorskip("_interpreters", reason="needs the subinterpreter module from Python 3.13")

# Each case runs in a new process, because only the first import in a process
# decides which interpreter may use the module.
# `import djc_core` alone loads only the Python package, so this uses a function
# from the compiled module.
_IMPORT = "from djc_core.html_transformer import set_html_attributes"


def _run(body: str, cwd: Path) -> str:
    script = "import _interpreters as I\n" + textwrap.dedent(body)
    # Outside the repository, so `-c` does not find the source folder before the wheel.
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, check=True, cwd=cwd)
    return result.stdout


class TestSubinterpreters:
    def test_second_interpreter_is_refused(self, tmp_path):
        out = _run(f"""
            {_IMPORT}
            print(set_html_attributes("<div></div>", ["a"], []))
            interp = I.create("legacy")
            failure = I.exec(interp, {_IMPORT!r})
            print(failure.type.__name__, failure.msg)
            I.destroy(interp)
        """, tmp_path)
        assert "ImportError djc_core can only be imported in one interpreter per process" in out

    def test_first_import_in_a_subinterpreter_is_allowed(self, tmp_path):
        # A single application in a mod_wsgi sub-interpreter imports it this way.
        out = _run(f"""
            interp = I.create("legacy")
            print("failure:", I.exec(interp, {_IMPORT!r}))
            I.destroy(interp)
        """, tmp_path)
        assert "failure: None" in out

    def test_repeat_import_in_same_interpreter_is_allowed(self, tmp_path):
        out = _run("""
            import sys
            from djc_core.html_transformer import set_html_attributes
            for name in [n for n in sys.modules if n.startswith("djc_core")]:
                del sys.modules[name]
            from djc_core.html_transformer import set_html_attributes
            print("ok")
        """, tmp_path)
        assert "ok" in out
