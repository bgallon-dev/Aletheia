from pathlib import Path

import pytest

from aletheia.store.repository import AletheiaRepository, RepositoryError


def test_object_path_uses_two_char_fanout(tmp_path):
    repo = AletheiaRepository(str(tmp_path), auto_init=True)
    object_id = "ab" + ("0" * 62)
    expected = Path(tmp_path) / "objects" / "ab" / object_id
    assert repo._object_path(object_id) == expected


def test_get_object_path_none_for_missing_valid_object(tmp_path):
    repo = AletheiaRepository(str(tmp_path), auto_init=True)
    assert repo.get_object_path("f" * 64) is None


def test_get_object_path_rejects_invalid_object_id(tmp_path):
    repo = AletheiaRepository(str(tmp_path), auto_init=True)
    with pytest.raises(RepositoryError):
        repo.get_object_path("not-a-valid-hash")
