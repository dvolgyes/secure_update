from pathlib import Path

from secure_update.scanner import find_lock_files


def test_finds_single_lock_file(tmp_path: Path) -> None:
    lock = tmp_path / "project" / "uv.lock"
    lock.parent.mkdir()
    lock.touch()
    result = find_lock_files([tmp_path])
    assert result == [lock]


def test_finds_nested_lock_files(tmp_path: Path) -> None:
    a = tmp_path / "a" / "uv.lock"
    b = tmp_path / "b" / "sub" / "uv.lock"
    a.parent.mkdir()
    b.parent.mkdir(parents=True)
    a.touch()
    b.touch()
    result = find_lock_files([tmp_path])
    assert set(result) == {a, b}


def test_skips_nonexistent_directory(tmp_path: Path) -> None:
    result = find_lock_files([tmp_path / "does_not_exist"])
    assert result == []


def test_returns_empty_when_no_lock_files(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    result = find_lock_files([tmp_path])
    assert result == []


def test_multiple_directories(tmp_path: Path) -> None:
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    (dir_a / "uv.lock").touch()
    result = find_lock_files([dir_a, dir_b])
    assert len(result) == 1
