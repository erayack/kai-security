from pathlib import Path

from kai.utils.framework import detect_framework


def test_detect_framework_adapter_c_maps_to_c(tmp_path: Path):
    assert detect_framework(tmp_path, adapter="c") == "c"


def test_detect_framework_makefile_detects_c(tmp_path: Path):
    (tmp_path / "Makefile").write_text("all:\n\techo ok\n")
    assert detect_framework(tmp_path) == "c"


def test_detect_framework_nested_c_sources_detect_c(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.c").write_text("int main(void) { return 0; }\n")
    assert detect_framework(tmp_path) == "c"
