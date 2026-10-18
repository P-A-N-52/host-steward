import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

PROJECT = Path(__file__).resolve().parents[1]


class RuntimeTests(unittest.TestCase):
    def test_runtime_files_support_independent_agent_sessions(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            runtime = base / "运行 skill"
            runtime.mkdir()
            shutil.copy2(PROJECT / "SKILL.md", runtime / "SKILL.md")
            for name in ["guidance", "tools", "state"]:
                shutil.copytree(PROJECT / name, runtime / name,
                                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

            root = base / "观察目录"
            root.mkdir()
            target = root / "原始资料.txt"
            target.write_text("需要长期保留的原始资料", encoding="utf-8")
            state = base / "本机状态"
            record = base / "资源定义.json"
            definition = json.loads((runtime / "state/resource.example.json").read_text(encoding="utf-8"))
            definition.update(id="runtime.original", kind="file", locator=str(target),
                              purpose="独立轮次应能读回的原始资料", owner="样例用户",
                              dependencies=["隔离测试项目"], retention="长期保留",
                              maintenance="原位只读检查", basis="observed",
                              source="隔离样例现场登记", evidence_at=time.time())
            record.write_text(json.dumps(definition, ensure_ascii=False), encoding="utf-8")

            command = [sys.executable, str(runtime / "tools/steward.py")]
            environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
            environment.pop("PYTHONPATH", None)
            help_result = subprocess.run(command + ["--help"], cwd="/", capture_output=True,
                                         text=True, timeout=10, env=environment)
            self.assertEqual(help_result.returncode, 0, help_result.stderr)
            self.assertIn("init", help_result.stdout)

            outputs = {}
            actions = [
                ("init", ["init", "--state", str(state), "--root", str(root),
                          "--purpose", "独立运行交付测试"]),
                ("patrol", ["patrol", "--state", str(state)]),
                ("status", ["status", "--state", str(state), "--path", str(root)]),
                ("record", ["inventory", "--state", str(state), "--record", str(record)]),
                ("query", ["inventory", "--state", str(state), "--id", definition["id"]]),
            ]
            for name, arguments in actions:
                with self.subTest(action=name):
                    result = subprocess.run(command + arguments, cwd="/", capture_output=True,
                                            text=True, timeout=30, env=environment)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    outputs[name] = json.loads(result.stdout)

            self.assertEqual(outputs["init"]["status"], "initialized")
            self.assertEqual(outputs["init"]["state"], str(state))
            self.assertIsNotNone(outputs["status"]["last_run"])
            self.assertIn(str(root), [row["path"] for row in outputs["status"]["directory_index"]])
            self.assertEqual(outputs["query"]["resources"][0]["definition"], definition)
            self.assertTrue((state / "guidance/patrol.md").is_file())
            self.assertTrue((state / "steward.sqlite3").is_file())
            self.assertFalse((state / "current.json").exists())
            self.assertFalse((state / "inventory.json").exists())
            self.assertFalse((state / "operations.json").exists())
            self.assertEqual(target.read_text(encoding="utf-8"), "需要长期保留的原始资料")
            self.assertEqual({path.name for path in runtime.iterdir()},
                             {"SKILL.md", "guidance", "tools", "state"})


if __name__ == "__main__":
    unittest.main()
