import hashlib
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))
from inventory import query, read_definition, read_inventory, register
from investigate import Budget, inspect_target, process_and_sockets, reference_search, startup_service
from maintain import quarantine
from state import Store, StewardError, encode
from steward import initialize


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "root"
        self.root.mkdir()
        self.target = self.root / "original.txt"
        self.target.write_text("original")
        self.store, self.policy = initialize(self.base / "state", [self.root], "隔离档案测试")
        self.definition = {"id": "original", "kind": "file", "locator": str(self.target),
                           "purpose": "原始资料", "owner": "样例用户", "dependencies": ["未完成的演示项目"],
                           "retention": "长期保留", "maintenance": "原位观察", "basis": "reported",
                           "source": "一份历史记录，尚未独立核验", "evidence_at": time.time() - 72 * 3600,
                           "review_after_hours": 24}

    def tearDown(self):
        self.temporary.cleanup()

    def test_old_evidence_survives_event_window_and_stays_due_after_inspection(self):
        register(self.store, self.definition)
        result = inspect_target(self.store, self.policy, "original")
        self.assertTrue(result["knowledge"]["review_due"])
        self.assertEqual(query(self.store, self.policy, "original")["resources"][0]["definition"]["evidence_at"],
                         self.definition["evidence_at"])
        self.store.write("current.json", {"changes": []})
        self.assertEqual(query(self.store, self.policy, "original")["resources"][0]["definition"]["retention"], "长期保留")

    def test_knowledge_does_not_grant_maintenance_or_rewrite_host_policy(self):
        before = self.store.target("host.json").read_bytes()
        definition = dict(self.definition, maintenance="建议删除", basis="user_statement")
        register(self.store, definition)
        inspect_target(self.store, self.policy, "original")
        with self.assertRaises(StewardError):
            quarantine(self.store, self.policy, self.target, True)
        self.assertEqual(before, self.store.target("host.json").read_bytes())
        self.assertTrue(self.target.is_file())
        with self.assertRaises(StewardError):
            register(self.store, dict(definition, allow_quarantine=True))

    def test_invalid_definitions_do_not_create_inventory(self):
        for field, value in [("kind", []), ("evidence_at", float("nan")), ("review_after_hours", True),
                             ("source", "x" * 1025), ("locator", "relative/path")]:
            with self.subTest(field=field), self.assertRaises(StewardError):
                register(self.store, dict(self.definition, **{field: value}))
        self.assertEqual(read_inventory(self.store)["resources"], {})

    def test_inspection_stores_policy_references_without_an_authorization_copy(self):
        self.policy["directory_rules"] = [{"path": str(self.root), "purpose": "重要资料", "kind": "cold", "allow_notes": True}]
        register(self.store, self.definition)
        report = inspect_target(self.store, self.policy, "original")
        saved = read_inventory(self.store)["resources"]["original"]["inspection"]
        self.assertEqual(report["policy"], {"source": "host.json", "directory_rule_path": str(self.root)})
        self.assertNotIn("knowledge", saved)
        self.assertNotIn("allow_notes", encode(saved).decode())
        self.policy["directory_rules"] = []
        self.assertIsNone(query(self.store, self.policy, "original")["resources"][0]["policy"]["directory_rule_path"])

    def test_corruption_and_capacity_failure_preserve_previous_inventory(self):
        register(self.store, self.definition)
        before = self.store.target("inventory.json").read_bytes()
        small = Store(self.store.path, dict(self.policy["limits"], total_bytes=self.store.usage() + 1))
        with self.assertRaises(StewardError):
            register(small, dict(self.definition, purpose="新的用途"))
        self.assertEqual(before, self.store.target("inventory.json").read_bytes())
        self.store.target("inventory.json").write_text('{"version":1,"resources":[]}')
        with self.assertRaises(StewardError):
            read_inventory(self.store)
        self.assertEqual(self.store.target("inventory.json").read_text(), '{"version":1,"resources":[]}')

    def test_identity_change_remains_visible_on_repeated_inspections(self):
        register(self.store, self.definition)
        inspect_target(self.store, self.policy, "original")
        replacement = self.root / "replacement.txt"
        replacement.write_text("replacement contents")
        os.replace(replacement, self.target)
        first = inspect_target(self.store, self.policy, "original")
        self.assertEqual(first["identity_continuity"], "changed")
        self.assertEqual(first["metadata_continuity"], "not_comparable")
        self.assertTrue(first["knowledge"]["identity_review_required"])
        size = self.store.target("inventory.json").stat().st_size
        for _ in range(3):
            self.assertEqual(inspect_target(self.store, self.policy, "original")["identity_continuity"], "changed")
        self.assertLess(self.store.target("inventory.json").stat().st_size, size + 256)
        register(self.store, dict(self.definition, evidence_at=time.time(), source="现场复核后的新来源"))
        self.assertEqual(inspect_target(self.store, self.policy, "original")["identity_continuity"], "baseline_created")

    def test_metadata_change_does_not_trigger_identity_review(self):
        register(self.store, self.definition)
        baseline = inspect_target(self.store, self.policy, "original")
        self.assertEqual(baseline["metadata_continuity"], "baseline_created")
        with self.target.open("a") as stream:
            stream.write(" and ordinary growth")
        changed = inspect_target(self.store, self.policy, "original")
        self.assertEqual(changed["identity_continuity"], "same")
        self.assertEqual(changed["metadata_continuity"], "changed")
        self.assertFalse(changed["knowledge"]["identity_review_required"])
        same = inspect_target(self.store, self.policy, "original")
        self.assertEqual(same["identity_continuity"], "same")
        self.assertEqual(same["metadata_continuity"], "same")
        self.assertFalse(same["knowledge"]["identity_review_required"])

    def test_legacy_file_anchor_matches_stable_generation_without_rewrite(self):
        register(self.store, self.definition)
        baseline = inspect_target(self.store, self.policy, "original")
        data = read_inventory(self.store)
        legacy_anchor = (f"{baseline['identity']}:{baseline['object']['size_bytes']}:"
                         f"{baseline['object']['mtime_ns']}")
        data["resources"]["original"]["anchor"] = legacy_anchor
        self.store.write("inventory.json", data)
        with self.target.open("a") as stream:
            stream.write(" and later growth")
        report = inspect_target(self.store, self.policy, "original")
        self.assertEqual(report["identity_continuity"], "same")
        self.assertEqual(report["metadata_continuity"], "changed")
        self.assertFalse(report["knowledge"]["identity_review_required"])
        self.assertEqual(read_inventory(self.store)["resources"]["original"]["anchor"], legacy_anchor)

    def test_identity_review_latch_survives_missing_and_same_generation(self):
        register(self.store, self.definition)
        baseline = inspect_target(self.store, self.policy, "original")
        self.assertEqual(baseline["identity_continuity"], "baseline_created")
        self.assertFalse(baseline["knowledge"]["identity_review_required"])
        retained = self.root / "retained-original.txt"
        self.target.rename(retained)
        self.target.write_text("replacement generation")
        changed = inspect_target(self.store, self.policy, "original")
        self.assertEqual(changed["identity_continuity"], "changed")
        self.assertTrue(changed["knowledge"]["identity_review_required"])
        self.target.unlink()
        missing = inspect_target(self.store, self.policy, "original")
        self.assertEqual(missing["identity_continuity"], "not_observed")
        self.assertTrue(missing["knowledge"]["identity_review_required"])
        retained.rename(self.target)
        same = inspect_target(self.store, self.policy, "original")
        self.assertEqual(same["identity_continuity"], "same")
        self.assertTrue(same["knowledge"]["identity_review_required"])
        self.assertTrue(read_inventory(self.store)["resources"]["original"]["inspection"]["identity_review_required"])

    def test_legacy_changed_inspection_without_latch_stays_required(self):
        register(self.store, self.definition)
        data = read_inventory(self.store)
        data["resources"]["original"]["inspection"] = {
            "target": str(self.target), "observed_at": time.time(), "startup": {},
            "identity_continuity": "changed"
        }
        self.store.write("inventory.json", data)
        item = query(self.store, self.policy, "original")["resources"][0]
        self.assertTrue(item["identity_review_required"])
        self.assertNotIn("identity_review_required", item["inspection"])
        report = inspect_target(self.store, self.policy, "original")
        self.assertTrue(report["knowledge"]["identity_review_required"])
        self.assertTrue(read_inventory(self.store)["resources"]["original"]["inspection"]["identity_review_required"])

    def test_invalid_identity_review_latch_preserves_inventory(self):
        register(self.store, self.definition)
        data = read_inventory(self.store)
        data["resources"]["original"]["inspection"] = {
            "target": str(self.target), "observed_at": time.time(), "startup": {},
            "identity_continuity": "same", "identity_review_required": "yes"
        }
        self.store.write("inventory.json", data)
        before = self.store.target("inventory.json").read_bytes()
        with self.assertRaises(StewardError):
            read_inventory(self.store)
        self.assertEqual(before, self.store.target("inventory.json").read_bytes())

    def test_same_definition_registration_does_not_clear_identity_review_latch(self):
        register(self.store, self.definition)
        data = read_inventory(self.store)
        data["resources"]["original"]["inspection"] = {
            "target": str(self.target), "observed_at": time.time(), "startup": {},
            "identity_continuity": "changed", "identity_review_required": True
        }
        self.store.write("inventory.json", data)
        result = register(self.store, self.definition)
        self.assertEqual(result, {"status": "unchanged", "id": "original"})
        self.assertTrue(query(self.store, self.policy, "original")["resources"][0]["identity_review_required"])

    def test_replacing_definition_rebuilds_anchor_and_clears_identity_review_latch(self):
        register(self.store, self.definition)
        data = read_inventory(self.store)
        data["resources"]["original"].update(anchor="old-anchor", inspection={
            "target": str(self.target), "observed_at": time.time(), "startup": {},
            "identity_continuity": "changed", "identity_review_required": True
        })
        self.store.write("inventory.json", data)
        updated = dict(self.definition, evidence_at=time.time(), source="现场复核后的新来源")
        result = register(self.store, updated)
        self.assertEqual(result["status"], "registered")
        saved = read_inventory(self.store)["resources"]["original"]
        self.assertEqual(saved["definition"]["evidence_at"], updated["evidence_at"])
        self.assertEqual(saved["definition"]["source"], "现场复核后的新来源")
        self.assertIsNone(saved["anchor"])
        self.assertIsNone(saved["inspection"])
        self.assertFalse(query(self.store, self.policy, "original")["resources"][0]["identity_review_required"])

    def test_first_unobserved_inspection_does_not_require_identity_review(self):
        register(self.store, self.definition)
        self.target.unlink()
        report = inspect_target(self.store, self.policy, "original")
        self.assertEqual(report["identity_continuity"], "not_observed")
        self.assertFalse(report["knowledge"]["identity_review_required"])
        saved = read_inventory(self.store)["resources"]["original"]["inspection"]
        self.assertFalse(saved["identity_review_required"])

    def test_definition_reader_rejects_special_files_and_oversize_without_blocking(self):
        valid = self.base / "definition.json"
        valid.write_bytes(encode(self.definition))
        self.assertEqual(read_definition(valid), self.definition)
        fifo = self.base / "definition.fifo"
        os.mkfifo(fifo)
        directory = self.base / "definition-directory"
        directory.mkdir()
        link = self.base / "definition-link"
        link.symlink_to(valid)
        oversized = self.base / "definition-oversized.json"
        oversized.write_bytes(b"x" * 8193)
        for candidate in (fifo, directory, link, oversized):
            with self.subTest(candidate=candidate):
                started = time.monotonic()
                with self.assertRaises(StewardError):
                    read_definition(candidate)
                self.assertLess(time.monotonic() - started, 1.0)

    def test_nonfinite_or_unbounded_times_are_corruption_not_fresh_evidence(self):
        register(self.store, self.definition)
        original = read_inventory(self.store)
        for field in ("recorded_at", "inspection"):
            for value in (float("nan"), 10**400):
                with self.subTest(field=field, value=value):
                    data = json.loads(json.dumps(original))
                    data["resources"]["original"][field] = (value if field == "recorded_at" else
                        {"target": str(self.target), "observed_at": value, "startup": {}})
                    self.store.write("inventory.json", data)
                    before = self.store.target("inventory.json").read_bytes()
                    with self.assertRaises(StewardError):
                        query(self.store, self.policy, "original")
                    self.assertEqual(before, self.store.target("inventory.json").read_bytes())

    def test_literal_references_return_locations_and_roles_without_secret_values(self):
        secret = "API_KEY_NEVER_EMIT_19358"
        (self.root / "app.json").write_text(json.dumps({"archive": str(self.target), "key": secret}))
        (self.root / "notes.md").write_text(str(self.target))
        (self.root / "script.py").write_text(repr(str(self.target)))
        register(self.store, self.definition)
        report = inspect_target(self.store, self.policy, "original")
        self.assertNotIn(secret, encode(report).decode())
        self.assertNotIn(secret, self.store.target("inventory.json").read_text())
        self.assertEqual({row["role"] for row in report["references"]["items"]}, {"configuration", "documentation", "source"})
        self.assertTrue(report["references"]["root_coverage"][0]["complete_within_declared_filters"])

    def test_unregistered_and_unavailable_are_distinct_from_no_reference_match(self):
        self.assertEqual(query(self.store, self.policy, "missing")["status"], "not_registered")
        with self.assertRaises(StewardError):
            inspect_target(self.store, self.policy, "missing")
        register(self.store, self.definition)
        self.target.unlink()
        report = inspect_target(self.store, self.policy, "original")
        self.assertEqual(report["identity_continuity"], "not_observed")
        self.assertTrue(any(row["reason"] == "target_errno_2" for row in report["budget"]["gaps"]))
        self.assertEqual(report["references"]["matches"], 0)

    def test_reference_scan_limits_files_bytes_and_depth_without_following_symlinks(self):
        outside = self.base / "outside.conf"
        outside.write_text(str(self.target))
        (self.root / "alias.conf").symlink_to(outside)
        with (self.root / "huge.conf").open("wb") as stream:
            stream.truncate(8 * 1024**2)
        for index in range(105):
            (self.root / f"small-{index}.json").write_text("{}")
        budget = Budget(self.policy["limits"])
        report = reference_search(str(self.target), self.policy, self.store, budget)
        self.assertLessEqual(budget.files, 100)
        self.assertLessEqual(budget.bytes, budget.max_bytes)
        self.assertFalse(report["root_coverage"][0]["complete_within_declared_filters"])
        self.assertFalse(any(row["path"].endswith("alias.conf") for row in report["items"]))
        budget = Budget(dict(self.policy["limits"], file_bytes=4))
        reference_search(str(self.target), self.policy, self.store, budget)
        self.assertLessEqual(budget.bytes, 4)

    def test_fifo_and_outside_target_are_not_read(self):
        fifo = self.root / "pipe.conf"
        os.mkfifo(fifo)
        budget = Budget(self.policy["limits"])
        self.assertIsNone(budget.read(fifo))
        report = inspect_target(self.store, self.policy, path=str(self.base / "outside"))
        self.assertIsNone(report["identity"])
        self.assertFalse(report["recording"]["saved"])
        self.assertTrue(any(row["reason"] == "path_outside_roots_or_symlink" for row in report["budget"]["gaps"]))

    def test_command_probe_counts_raw_bytes_within_shared_budget(self):
        budget = Budget(dict(self.policy["limits"], file_bytes=128))
        result = budget.run([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'\\xff'*1000)"], "byte limit fixture")
        self.assertIsNone(result)
        self.assertLessEqual(budget.bytes, 128)
        self.assertTrue(budget.gaps)

    def test_socket_metadata_reports_truncation_without_process_arguments(self):
        sockets = "p42\n" + "".join(f"f{index}\nPTCP\nn127.0.0.1:{10000 + index}\nTST=LISTEN\n" for index in range(40))
        responses = ["42 1 Fri Oct 16 10:00:00 2026 0.0 100 /usr/bin/example\n", sockets]
        with patch("investigate.platform.system", return_value="Darwin"), \
             patch("investigate.command", side_effect=[{"ok": True, "reason": None, "text": text} for text in responses]):
            report = process_and_sockets(42, Budget(self.policy["limits"]))
        self.assertEqual(len(report["sockets"]), 32)
        self.assertEqual(report["socket_records_observed"], 40)
        self.assertTrue(report["socket_records_truncated"])
        self.assertEqual(report["sockets"][0]["state"], "LISTEN")

    def test_macos_idle_job_resolves_relative_program_using_working_directory(self):
        native = self.base / "LaunchAgents"
        native.mkdir()
        program = self.base / "application/bin/app"
        program.parent.mkdir(parents=True)
        program.write_text("fixture")
        source = native / "example.job.plist"
        source.write_bytes(plistlib.dumps({"Label": "example.job", "ProgramArguments": ["./bin/app", "DO_NOT_EMIT_ARGUMENT"],
                                          "WorkingDirectory": str(program.parent.parent), "StartInterval": 3600,
                                          "EnvironmentVariables": {"SECRET": "DO_NOT_EMIT_ENV"}}))
        failure = {"ok": False, "reason": "command_failed", "text": "DO_NOT_EMIT_ERROR_CONTENT"}
        with patch("investigate.platform.system", return_value="Darwin"), \
             patch("investigate.startup_directories", return_value=[native]), patch("investigate.command", return_value=failure):
            budget = Budget(self.policy["limits"])
            report = startup_service("launchd:user/example.job", budget)
        self.assertIsNone(report["pid"])
        self.assertTrue(report["program_exists"])
        self.assertEqual(report["resolved_program"], str(program))
        self.assertEqual(report["start_interval"], 3600)
        self.assertNotIn("DO_NOT_EMIT", encode(report).decode())
        self.assertTrue(budget.gaps)

    def test_systemd_user_scope_and_effective_executable_do_not_emit_arguments(self):
        native = self.base / "systemd-user"
        native.mkdir()
        source = native / "example.service"
        source.write_text("[Service]\nExecStart=/bin/sh secret-value\n")
        output = f"Id=example.service\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=42\nFragmentPath={source}\nDropInPaths=\nWorkingDirectory=/\nExecStart={{ path=/bin/sh ; argv[]=/bin/sh SECRET_ARGS ; }}\n"
        with patch("investigate.platform.system", return_value="Linux"), \
             patch("investigate.startup_directories", return_value=[native]), \
             patch("investigate.command", return_value={"ok": True, "reason": None, "text": output}) as call:
            report = startup_service("systemd:user/example.service", Budget(self.policy["limits"]))
        self.assertIn("--user", call.call_args[0][0])
        self.assertEqual(report["pid"], 42)
        self.assertEqual(report["resolved_program"], "/bin/sh")
        self.assertNotIn("SECRET_ARGS", encode(report).decode())
        self.assertNotIn("secret-value", encode(report).decode())
        self.assertEqual(len(report["configurations"]), 1)

    def test_cli_reads_persisted_definition_in_a_separate_shell_and_cwd(self):
        definition = self.base / "definition.json"
        definition.write_text(json.dumps(self.definition))
        prefix = [str(PROJECT / "steward")]
        before = hashlib.sha256(self.store.target("host.json").read_bytes()).hexdigest()
        writer = subprocess.run(["/bin/bash", *prefix, "inventory", "--state", str(self.store.path), "--record", str(definition)],
                                cwd="/", capture_output=True, text=True, timeout=5)
        self.assertEqual(writer.returncode, 0, writer.stderr)
        shell = "/bin/zsh" if Path("/bin/zsh").exists() else "/bin/bash"
        reader = subprocess.run([shell, *prefix, "inventory", "--state", str(self.store.path), "--id", "original"],
                                cwd="/", capture_output=True, text=True, timeout=5)
        self.assertEqual(reader.returncode, 0, reader.stderr)
        data = json.loads(reader.stdout)["resources"][0]
        self.assertEqual(data["definition"]["purpose"], "原始资料")
        self.assertTrue(data["review_due"])
        self.assertEqual(before, hashlib.sha256(self.store.target("host.json").read_bytes()).hexdigest())

    def test_definition_format_errors_block_api_and_cli_without_state_changes(self):
        definition = self.base / "bad-definition.json"
        before = self.store.target("inventory.json").read_bytes()
        payloads = [b"{", b'{"id":1,"id":2}', b'{"value":NaN}', b'{"value":1e309}',
                    b"\xff", b"[" * 2000 + b"]" * 2000]
        for index, payload in enumerate(payloads):
            with self.subTest(case=index):
                definition.write_bytes(payload)
                with self.assertRaises(StewardError):
                    read_definition(definition)
                result = subprocess.run([str(PROJECT / "steward"), "inventory", "--state", str(self.store.path),
                                         "--record", str(definition)], cwd="/", capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(json.loads(result.stderr)["status"], "blocked")
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(self.store.target("inventory.json").read_bytes(), before)

    def test_alias_definition_is_rejected_and_query_is_read_only_canonical(self):
        alias = self.base / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(StewardError):
            register(self.store, dict(self.definition, locator=str(alias / "original.txt")))
        self.assertEqual(read_inventory(self.store)["resources"], {})
        register(self.store, self.definition)
        before = self.store.target("inventory.json").read_bytes()
        result = query(self.store, self.policy, path=str(alias))
        self.assertEqual(result["total"], 1)
        self.assertFalse(result["resources"][0]["legacy_noncanonical"])
        for path in ("", "bad\x00path"):
            with self.subTest(path=path), self.assertRaises(StewardError):
                query(self.store, self.policy, path=path)
        self.assertEqual(self.store.target("inventory.json").read_bytes(), before)

    def test_legacy_alias_inventory_is_readable_but_inspection_is_not_overwritten(self):
        alias = self.base / "legacy-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        definition = dict(self.definition, locator=str(alias / "original.txt"))
        entry = {"definition": definition, "recorded_at": time.time(), "anchor": "old-anchor",
                 "inspection": {"target": definition["locator"], "observed_at": time.time(),
                                "startup": {}, "custom": "keep"}}
        self.store.write("inventory.json", {"version": 1, "resources": {"original": entry}})
        before = self.store.target("inventory.json").read_bytes()
        self.assertEqual(read_inventory(self.store)["resources"]["original"]["definition"]["locator"], definition["locator"])
        queried = query(self.store, self.policy, path=str(self.root))
        self.assertEqual(queried["total"], 1)
        self.assertTrue(queried["resources"][0]["legacy_noncanonical"])
        self.assertEqual(queried["resources"][0]["inspection"], entry["inspection"])
        report = inspect_target(self.store, self.policy, "original")
        self.assertEqual(report["status"], "migration_required")
        self.assertFalse(report["recording"]["saved"])
        self.assertIn("migration", report["recording"]["reason"])
        self.assertEqual(self.store.target("inventory.json").read_bytes(), before)

    def test_legacy_alias_retarget_does_not_attach_new_policy_to_old_evidence(self):
        original = self.root / "a"
        replacement = self.root / "b"
        original.mkdir()
        replacement.mkdir()
        alias = self.root / "legacy"
        alias.symlink_to(original, target_is_directory=True)
        definition = dict(self.definition, locator=str(alias / "original.txt"))
        entry = {"definition": definition, "recorded_at": time.time(), "anchor": "old-anchor", "inspection": None}
        self.store.write("inventory.json", {"version": 1, "resources": {"original": entry}})
        before = self.store.target("inventory.json").read_bytes()
        self.policy["directory_rules"] = [{"path": str(replacement), "purpose": "new", "kind": "cold"}]
        alias.unlink()
        alias.symlink_to(replacement, target_is_directory=True)
        item = query(self.store, self.policy, "original")["resources"][0]
        self.assertTrue(item["legacy_noncanonical"])
        self.assertIsNone(item["policy"]["directory_rule_path"])
        self.assertEqual(item["definition"]["locator"], definition["locator"])
        self.assertEqual(self.store.target("inventory.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
