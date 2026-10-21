import re
import unittest
from pathlib import Path

GO_TASKS = Path(__file__).resolve().parents[1] / "roles" / "controller-baseline" / "tasks" / "go.yml"


def link_pattern(name):
    text = GO_TASKS.read_text()
    found = re.search(r"match\('(\^/opt/boetticher/toolchains/[^']+/bin/)' \+ \(item\.item\.path \| basename\) \+ '\$'\)", text)
    if not found:
        raise AssertionError("public Go link ownership pattern not found in go.yml")
    # YAML keeps the backslashes; the Jinja string literal halves them.
    return re.compile(found.group(1).replace("\\\\", "\\") + re.escape(name) + "$")


class GoToolchainLinkOwnership(unittest.TestCase):
    def test_links_into_earlier_or_current_owned_toolchains_may_move(self):
        for name, source in (
            ("gofmt", "/opt/boetticher/toolchains/go1.26.6/bin/gofmt"),
            ("go", "/opt/boetticher/toolchains/go1.26.10/bin/go"),
            ("go", "/opt/boetticher/toolchains/go1.27/bin/go"),
        ):
            self.assertTrue(link_pattern(name).match(source), source)

    def test_unrelated_or_mismatched_links_are_refused(self):
        for name, source in (
            ("go", "/usr/lib/go-1.24/bin/go"),
            ("go", "/opt/boetticher/toolchains/go1.26.6/bin/gofmt"),
            ("gofmt", "/opt/boetticher/toolchains/go1.26.6/../evil/bin/gofmt"),
            ("go", "/opt/boetticher/toolchains/gox/bin/go"),
        ):
            self.assertFalse(link_pattern(name).match(source), source)


if __name__ == "__main__":
    unittest.main()
