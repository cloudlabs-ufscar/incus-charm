from pathlib import Path

from ceph import write_keyring_file
from src.ceph import write_ceph_conf_file


def test_write_keyring_file(tmp_path: Path):
    """Test writing the Ceph keyring file.

    The file should be created with the appropriate contents.
    """
    ceph_dir = tmp_path / "ceph"
    keyring_file = ceph_dir / "ceph.client.any-ceph-user.keyring"
    assert not keyring_file.exists()

    write_keyring_file("any-ceph-user", "any-key", ceph_dir=ceph_dir)
    assert keyring_file.exists()
    assert keyring_file.read_text() == "[client.any-ceph-user]\nkey = any-key\n\n"


def test_write_keyring_file_override_file(tmp_path: Path):
    """Test writing the Ceph keyring file when the file already exists.

    The file should be overwritten with the appropriate contents.
    """
    ceph_dir = tmp_path / "ceph"
    keyring_file = ceph_dir / "ceph.client.any-ceph-user.keyring"
    keyring_file.parent.mkdir()
    keyring_file.write_text("[client.any-ceph-user]\nkey = any-old-key")
    assert keyring_file.exists()
    assert keyring_file.read_text() == "[client.any-ceph-user]\nkey = any-old-key"

    write_keyring_file("any-ceph-user", "any-key", ceph_dir=ceph_dir)
    assert keyring_file.read_text() == "[client.any-ceph-user]\nkey = any-key\n\n"


def test_write_ceph_conf_file(tmp_path: Path):
    """Test writing the Ceph configuration.

    The file should be created with the appropriate contents.
    """
    ceph_dir = tmp_path / "ceph"
    conf_file = ceph_dir / "ceph.conf"
    assert not conf_file.exists()

    write_ceph_conf_file({"10.0.0.1", "10.0.0.2"}, ceph_dir=ceph_dir)
    assert conf_file.exists()
    assert conf_file.read_text() == "[global]\nmon host = 10.0.0.1 10.0.0.2\n\n"


def test_write_ceph_conf_file_override_file(tmp_path: Path):
    """Test writing the Ceph configuration when the file already exists.

    The file should be overwritten with the appropriate contents.
    """
    ceph_dir = tmp_path / "ceph"
    conf_file = ceph_dir / "ceph.conf"
    conf_file.parent.mkdir()
    existing_content = "[global]\nmon host = 10.0.0.1".strip()
    conf_file.write_text(existing_content)

    write_ceph_conf_file({"10.0.0.1", "10.0.0.2"}, ceph_dir=ceph_dir)
    assert conf_file.exists()
    assert conf_file.read_text() == "[global]\nmon host = 10.0.0.1 10.0.0.2\n\n"


def test_write_ceph_conf_file_preserve_file(tmp_path: Path):
    """Test writing the Ceph configuration when the file already exists but is not managed by the charm.

    The file should not be overwritten, and its contents should remain intact.
    """
    ceph_dir = tmp_path / "ceph"
    conf_file = ceph_dir / "ceph.conf"
    conf_file.parent.mkdir()
    existing_content = """
[global]
auth cluster required = cephx
auth service required = cephx
auth client required = cephx

mon host = 10.18.196.157 10.18.196.162 10.18.196.2""".strip()
    conf_file.write_text(existing_content)

    write_ceph_conf_file({"10.0.0.1", "10.0.0.2"}, ceph_dir=ceph_dir)
    assert conf_file.exists()
    assert conf_file.read_text() == existing_content
