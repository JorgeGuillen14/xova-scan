"""The README example must be the scanner's real output on the demo machine (no hand-written numbers)."""
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "examples"))


@unittest.skipIf(os.name == "nt", "the demo uses the macOS layout and POSIX paths")
class ReadmeTests(unittest.TestCase):
    def test_readme_example_is_real_demo_output(self):
        import demo_machine
        text = (ROOT / "README.md").read_text()
        block = text.split(demo_machine.START, 1)[1].split(demo_machine.END, 1)[0]
        expected = "\n```\n" + demo_machine.demo_output() + "```\n"
        self.assertEqual(block, expected, "README example drifted: run python3 examples/demo_machine.py --update-readme")


if __name__ == "__main__":
    unittest.main()
