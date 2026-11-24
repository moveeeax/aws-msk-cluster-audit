import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"
EXAMPLES = pathlib.Path(__file__).resolve().parents[1] / "examples" / "dump"


def fixture(name: str) -> str:
    path = FIXTURES / name
    assert path.exists(), f"missing fixture {path}"
    return str(path)
