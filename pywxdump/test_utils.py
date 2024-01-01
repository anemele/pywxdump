from .utils import compare_version


def test_cv():
    assert compare_version('3.2.1', '3.1.2') == 1
    assert compare_version('3.2.1', '3.2.1') == 0
    assert compare_version('3.2.1', '3.3.1') == -1
    assert compare_version('3.2.1.8', '3.3.1') == -1
    assert compare_version('3.10', '3.9') == 1
