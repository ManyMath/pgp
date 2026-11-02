import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_windows_wrapper as wrapper

REPO = Path(__file__).resolve().parents[2]
MANIFESTS = ["packages/pgp/rust/Cargo.toml", "packages/pgp/windows/rust/Cargo.toml"]


class WindowsWrapperTest(unittest.TestCase):
    def copy(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        for name in MANIFESTS:
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / name, root / name)
        return root

    def test_repository_wrapper_matches(self):
        self.assertEqual(wrapper.check(REPO), [])

    def test_dependency_added_to_crate_only_is_reported(self):
        root = self.copy()
        crate = root / MANIFESTS[0]
        crate.write_text(crate.read_text().replace('anyhow = "1"\n', 'anyhow = "1"\nzeroize = "1"\n'))
        self.assertTrue(any("dependencies differ" in p for p in wrapper.check(root)))

    def test_wrong_backend_is_reported(self):
        root = self.copy()
        manifest = root / MANIFESTS[1]
        manifest.write_text(manifest.read_text().replace('"crypto-cng"', '"crypto-rust"'))
        self.assertTrue(any("crypto-cng" in p for p in wrapper.check(root)))


if __name__ == "__main__":
    unittest.main()
