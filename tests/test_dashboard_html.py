import shutil
import subprocess
import unittest

from qproxy.dashboard import DASHBOARD_HTML


class DashboardHtmlTests(unittest.TestCase):
    def test_exposes_search_and_manual_block_controls(self):
        for token in (
            'id="search"',
            'id="rulesTable"',
            'id="blockForm"',
            'id="allowForm"',
            '/api/rules?',
            '/api/blocklist',
            '/api/whitelist',
            'id="sources"',
        ):
            with self.subTest(token=token):
                self.assertIn(token, DASHBOARD_HTML)

    @unittest.skipUnless(shutil.which("node"), "Node.js não instalado (opcional)")
    def test_dashboard_javascript_parses(self):
        script = DASHBOARD_HTML.split("<script>", 1)[1].split("</script>", 1)[0]
        # Node parses the script but does not execute browser-only APIs.
        outcome = subprocess.run(
            ["node", "--check", "--input-type=commonjs"],
            input=script,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(outcome.returncode, 0, outcome.stderr)


if __name__ == "__main__":
    unittest.main()
