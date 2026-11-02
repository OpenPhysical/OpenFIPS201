import types
import unittest
from pathlib import Path


SCRIPT_DIRECTORY = Path(__file__).resolve().parent


class OptimizedValidationTests(unittest.TestCase):
    def test_optimized_python_keeps_independent_kdf_validation(self):
        cases = (
            ("host_keytransport_vectors.py", "x963", (b"z", b"info")),
            ("sam_transport_vectors.py", "kdf", (b"z", b"transport", b"host", b"0001")),
        )

        for filename, function_name, arguments in cases:
            with self.subTest(filename=filename):
                path = SCRIPT_DIRECTORY / filename
                vectors = types.ModuleType("vectors")
                vectors.__file__ = str(path)
                # Execute only the checked-in fixture source to reproduce Python's optimized mode.
                exec(compile(path.read_text(), str(path), "exec", optimize=1), vectors.__dict__)  # nosec B102

                class MismatchingKdf:
                    def __init__(self, *args, **kwargs):
                        # Match X963KDF's constructor while deliberately replacing only derive().
                        return None

                    def derive(self, value):
                        return bytes(32)

                vectors.X963KDF = MismatchingKdf
                with self.assertRaises(RuntimeError):
                    getattr(vectors, function_name)(*arguments)


if __name__ == "__main__":
    unittest.main()
