import importlib
import pkgutil
import unittest

import wgwizard


class ImportEverything(unittest.TestCase):
    def test_every_module_imports(self):
        for mod in pkgutil.iter_modules(wgwizard.__path__):
            with self.subTest(module=mod.name):
                importlib.import_module(f"wgwizard.{mod.name}")


if __name__ == "__main__":
    unittest.main()
