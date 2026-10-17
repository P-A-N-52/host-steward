import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
SNAPSHOT = PROJECT / "references" / "upstream-skills"
sys.path.insert(0, str(PROJECT / "tools"))
from state import decode

SOURCE_FIELDS = {"repository", "commit", "skills", "documents", "license", "license_file"}
FILE_FIELDS = {"project", "source_path", "git_blob_sha1", "sha256", "bytes", "mode"}
MODES = {"100644", "100755"}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
LOCAL_FILES = {"README.md", "manifest.json"}


def _require(condition, message):
    if not condition:
        raise AssertionError(message)


def _relative(value, label):
    _require(isinstance(value, str) and value, f"{label} must be a non-empty relative path")
    _require("\x00" not in value and "\\" not in value, f"{label} contains an invalid character")
    parts = value.split("/")
    _require(not value.startswith("/") and all(part not in {"", ".", ".."} for part in parts),
             f"{label} must not be absolute or contain empty, dot, or parent components")
    return value


def _project_name(value, label):
    value = _relative(value, label)
    _require("/" not in value, f"{label} must name one project directory")
    return value


def _read_manifest(root):
    path = Path(root) / "manifest.json"
    try:
        _ensure_regular(Path(root), path, "manifest.json")
        return decode(path.read_bytes())
    except (OSError, ValueError, RecursionError) as exc:
        raise AssertionError(f"manifest.json is not strict valid JSON: {exc}") from exc


def _check_inside(root, path, label):
    root = Path(root)
    path = Path(path)
    _require(not root.is_symlink(), "snapshot root must not be a symlink")
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise AssertionError(f"{label} escapes the snapshot root") from exc
    current = path
    while True:
        _require(not current.is_symlink(), f"{label} or one of its parents is a symlink: {current}")
        if current == root:
            return
        parent = current.parent
        _require(parent != current, f"{label} is not below the snapshot root")
        current = parent


def _ensure_regular(root, path, label):
    path = Path(path)
    _check_inside(root, path, label)
    try:
        mode = os.lstat(path).st_mode
    except OSError as exc:
        raise AssertionError(f"{label} is missing or cannot be inspected: {path}") from exc
    _require(stat.S_ISREG(mode), f"{label} must be an ordinary file: {path}")
    return path


def _ensure_directory(root, path, label):
    path = Path(path)
    _check_inside(root, path, label)
    try:
        mode = os.lstat(path).st_mode
    except OSError as exc:
        raise AssertionError(f"{label} directory is missing or cannot be inspected: {path}") from exc
    _require(stat.S_ISDIR(mode), f"{label} must be a directory: {path}")
    return path


def _project_files(root, project):
    project_dir = _ensure_directory(root, Path(root) / project, f"project {project}")
    files = {}

    def onerror(error):
        raise AssertionError(f"cannot enumerate project {project}: {error}") from error

    for current, directories, names in os.walk(project_dir, topdown=True, followlinks=False, onerror=onerror):
        current_path = Path(current)
        for name in directories:
            child = current_path / name
            _ensure_directory(root, child, f"project {project} directory {child}")
        for name in names:
            child = current_path / name
            _ensure_regular(root, child, f"project {project} file {child}")
            relative = child.relative_to(project_dir).as_posix()
            _relative(relative, f"actual project path {project}/{relative}")
            files[(project, relative)] = child
    return files


def _file_record(project, relative, path):
    content = path.read_bytes()
    mode = os.lstat(path).st_mode & 0o170777
    blob = b"blob " + str(len(content)).encode() + b"\0" + content
    return {"project": project, "source_path": relative,
            "git_blob_sha1": hashlib.sha1(blob).hexdigest(),
            "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content),
            "mode": format(mode, "06o")}


def validate_snapshot(root):
    root = Path(root)
    _ensure_directory(root, root, "snapshot root")
    _ensure_regular(root, root / "manifest.json", "manifest.json")
    _ensure_regular(root, root / "README.md", "README.md")
    manifest = _read_manifest(root)
    _require(isinstance(manifest, dict), "manifest must be an object")
    _require("sources" in manifest and "files" in manifest, "manifest must contain sources and files")
    if "snapshot_date" in manifest:
        _require(isinstance(manifest["snapshot_date"], str), "snapshot_date must be a string")
    if "purpose" in manifest:
        _require(isinstance(manifest["purpose"], str), "purpose must be a string")

    sources = manifest["sources"]
    rows = manifest["files"]
    _require(isinstance(sources, dict) and sources, "sources must be a non-empty object")
    _require(isinstance(rows, list) and rows, "files must be a non-empty list")

    source_projects = set()
    for project, source in sources.items():
        project = _project_name(project, "source project")
        _require(project not in source_projects, f"duplicate source project: {project}")
        source_projects.add(project)
        _require(isinstance(source, dict) and set(source) == SOURCE_FIELDS,
                 f"source {project} has unexpected fields")
        _require(isinstance(source["repository"], str) and source["repository"],
                 f"source {project} repository must be a string")
        _require(isinstance(source["commit"], str) and HEX40.fullmatch(source["commit"]),
                 f"source {project} commit must be a 40-digit lowercase hex string")
        _require(isinstance(source["license"], str) and source["license"],
                 f"source {project} license must be a string")
        _require(isinstance(source["skills"], list) and source["skills"],
                 f"source {project} must list skills")
        _require(isinstance(source["documents"], list), f"source {project} documents must be a list")

    manifest_files = {}
    for index, row in enumerate(rows):
        _require(isinstance(row, dict) and set(row) == FILE_FIELDS,
                 f"file row {index} has unexpected fields")
        project = _project_name(row["project"], f"file row {index} project")
        _require(project in source_projects, f"file row {index} names an unknown project: {project}")
        relative = _relative(row["source_path"], f"file row {index} source_path")
        _require(isinstance(row["git_blob_sha1"], str) and HEX40.fullmatch(row["git_blob_sha1"]),
                 f"file row {index} has an invalid git_blob_sha1")
        _require(isinstance(row["sha256"], str) and HEX64.fullmatch(row["sha256"]),
                 f"file row {index} has an invalid sha256")
        _require(isinstance(row["bytes"], int) and not isinstance(row["bytes"], bool) and row["bytes"] >= 0,
                 f"file row {index} bytes must be a non-negative integer")
        _require(isinstance(row["mode"], str) and row["mode"] in MODES, f"file row {index} has an unsupported mode")
        key = (project, relative)
        _require(key not in manifest_files, f"duplicate manifest file path: {project}/{relative}")
        manifest_files[key] = row

    source_files = set()
    actual_files = {}
    for project, source in sources.items():
        project_files = _project_files(root, project)
        actual_files.update(project_files)

        def add_source_file(relative, label):
            relative = _relative(relative, label)
            key = (project, relative)
            _require(key in project_files, f"{label} is missing: {project}/{relative}")
            _require(key not in source_files, f"duplicate source path: {project}/{relative}")
            source_files.add(key)

        for skill_index, skill in enumerate(source["skills"]):
            skill = _relative(skill, f"source {project} skill {skill_index}")
            skill_label = f"source {project} skill {skill_index}"
            skill_dir = _ensure_directory(root, Path(root, project, *skill.split("/")), skill_label)
            prefix = skill + "/"
            skill_files = [key for key in project_files if key[1].startswith(prefix)]
            _require(skill_files, f"{skill_label} must not be empty")
            _require((project, prefix + "SKILL.md") in project_files,
                     f"{skill_label} must contain SKILL.md")
            for _, relative in skill_files:
                add_source_file(relative, f"{skill_label} file {relative}")

        for document_index, document in enumerate(source["documents"]):
            document = _relative(document, f"source {project} document {document_index}")
            add_source_file(document, f"source {project} document {document_index}")

        license_file = _relative(source["license_file"], f"source {project} license_file")
        license_parts = license_file.split("/")
        _require(license_parts[0] == project and len(license_parts) > 1,
                 f"source {project} license_file must be project-relative to the snapshot root")
        add_source_file("/".join(license_parts[1:]), f"source {project} license_file")

    _require(source_files == set(manifest_files),
             "manifest.files and source expansion differ: "
             f"missing={sorted(source_files - set(manifest_files))}, "
             f"extra={sorted(set(manifest_files) - source_files)}")
    _require(set(actual_files) == set(manifest_files),
             "manifest.files and actual project files differ: "
             f"missing={sorted(set(actual_files) - set(manifest_files))}, "
             f"extra={sorted(set(manifest_files) - set(actual_files))}")

    root_entries = {path.name for path in root.iterdir()}
    _require(root_entries <= source_projects | LOCAL_FILES,
             f"unexpected snapshot-root entries: {sorted(root_entries - source_projects - LOCAL_FILES)}")

    for key, row in manifest_files.items():
        project, relative = key
        path = actual_files[key]
        content = path.read_bytes()
        blob = b"blob " + str(len(content)).encode() + b"\0" + content
        observed = {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest(),
                    "git_blob_sha1": hashlib.sha1(blob).hexdigest(),
                    "mode": format(os.lstat(path).st_mode & 0o170777, "06o")}
        for field, value in observed.items():
            _require(row[field] == value,
                     f"{project}/{relative} {field} mismatch: {row[field]!r} != {value!r}")

    return manifest


def _write_manifest(root, manifest):
    (Path(root) / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n")


def _mutate_manifest(root, mutation):
    manifest = _read_manifest(root)
    mutation(manifest)
    _write_manifest(root, manifest)


def _fixture(root):
    root = Path(root)
    project = root / "demo"
    skill = project / "skills" / "example"
    documents = project / "docs"
    skill.mkdir(parents=True)
    documents.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# Example\n")
    script = skill / "run.sh"
    script.write_text("#!/bin/sh\nprintf example\n")
    script.chmod(0o755)
    (documents / "guide.md").write_text("A small reference.\n")
    (project / "LICENSE").write_text("MIT\n")
    (root / "README.md").write_text("Local snapshot notes.\n")

    files = []
    for relative in ["LICENSE", "skills/example/SKILL.md", "skills/example/run.sh", "docs/guide.md"]:
        files.append(_file_record("demo", relative, project / relative))
    manifest = {"snapshot_date": "2026-10-17", "purpose": "fixture",
                "sources": {"demo": {"repository": "https://example.invalid/demo", "commit": "a" * 40,
                                     "skills": ["skills/example"], "documents": ["docs/guide.md"],
                                     "license": "MIT", "license_file": "demo/LICENSE"}},
                "files": files}
    _write_manifest(root, manifest)
    return root


class ReferenceSnapshotTests(unittest.TestCase):
    def assert_fixture_rejected(self, mutation):
        with tempfile.TemporaryDirectory() as temporary:
            root = _fixture(Path(temporary) / "snapshot")
            mutation(root)
            with self.assertRaises(AssertionError):
                validate_snapshot(root)

    def test_real_snapshot_is_consistent(self):
        validate_snapshot(SNAPSHOT)

    def test_small_fixture_is_consistent_and_excludes_local_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _fixture(Path(temporary) / "snapshot")
            validate_snapshot(root)

    def test_tampering_and_each_digest_or_size_mismatch_fails(self):
        mutations = [
            ("content", lambda root: (root / "demo/docs/guide.md").write_text("tampered\n")),
            ("bytes", lambda root: _mutate_manifest(
                root, lambda manifest: manifest["files"][0].__setitem__("bytes", manifest["files"][0]["bytes"] + 1))),
            ("sha256", lambda root: _mutate_manifest(
                root, lambda manifest: manifest["files"][0].__setitem__("sha256", "0" * 64))),
            ("git blob", lambda root: _mutate_manifest(
                root, lambda manifest: manifest["files"][0].__setitem__("git_blob_sha1", "0" * 40))),
        ]
        for label, mutation in mutations:
            with self.subTest(kind=label):
                self.assert_fixture_rejected(mutation)

    def test_missing_file_and_missing_skill_document_fail(self):
        for relative in ["docs/guide.md", "skills/example/SKILL.md"]:
            with self.subTest(path=relative):
                self.assert_fixture_rejected(lambda root, relative=relative:
                                              (root / "demo" / relative).unlink())

    def test_unlisted_file_inside_skill_fails(self):
        self.assert_fixture_rejected(
            lambda root: (root / "demo/skills/example/unlisted.txt").write_text("not in manifest\n"))

    def test_mode_and_symlink_or_parent_symlink_fail(self):
        mutations = [
            ("mode", lambda root: (root / "demo/skills/example/run.sh").chmod(0o644)),
            ("file symlink", self._replace_file_with_symlink),
            ("parent symlink", self._replace_document_directory_with_symlink),
        ]
        for label, mutation in mutations:
            with self.subTest(kind=label):
                self.assert_fixture_rejected(mutation)

    @staticmethod
    def _replace_file_with_symlink(root):
        target = root / "demo/docs/guide.md"
        outside = root.parent / "outside-guide.md"
        outside.write_text("same bytes are not enough\n")
        target.unlink()
        target.symlink_to(outside)

    @staticmethod
    def _replace_document_directory_with_symlink(root):
        documents = root / "demo/docs"
        outside = root.parent / "outside-docs"
        outside.mkdir()
        (outside / "guide.md").write_text("A small reference.\n")
        shutil.rmtree(documents)
        documents.symlink_to(outside, target_is_directory=True)

    def test_relative_paths_reject_traversal_and_dot_components(self):
        mutations = [
            ("skill traversal", lambda manifest: manifest["sources"]["demo"]["skills"].__setitem__(0,
                                                                                                  "../skills/example")),
            ("document dot", lambda manifest: manifest["sources"]["demo"]["documents"].__setitem__(0,
                                                                                                       "./docs/guide.md")),
            ("license traversal", lambda manifest: manifest["sources"]["demo"].__setitem__(
                "license_file", "demo/../demo/LICENSE")),
            ("file traversal", lambda manifest: manifest["files"][0].__setitem__("source_path", "../LICENSE")),
        ]
        for label, mutation in mutations:
            with self.subTest(kind=label):
                self.assert_fixture_rejected(lambda root, mutation=mutation: _mutate_manifest(root, mutation))

    def test_duplicate_manifest_path_fails(self):
        self.assert_fixture_rejected(lambda root: _mutate_manifest(
            root, lambda manifest: manifest["files"].append(copy.deepcopy(manifest["files"][0]))))

    def test_source_and_file_fields_are_checked(self):
        mutations = [
            ("missing source field", lambda manifest: manifest["sources"]["demo"].pop("repository")),
            ("extra source field", lambda manifest: manifest["sources"]["demo"].__setitem__("extra", True)),
            ("missing file field", lambda manifest: manifest["files"][0].pop("mode")),
            ("extra file field", lambda manifest: manifest["files"][0].__setitem__("extra", True)),
            ("invalid mode type", lambda manifest: manifest["files"][0].__setitem__("mode", [])),
        ]
        for label, mutation in mutations:
            with self.subTest(kind=label):
                self.assert_fixture_rejected(lambda root, mutation=mutation: _mutate_manifest(root, mutation))

    def test_decode_rejects_duplicate_keys_and_nonfinite_numbers(self):
        payloads = [
            '{"sources":{},"sources":{}}',
            '{"sources":{},"files":[],"value":NaN}',
        ]
        for payload in payloads:
            with self.subTest(payload=payload):
                with tempfile.TemporaryDirectory() as temporary:
                    root = _fixture(Path(temporary) / "snapshot")
                    (root / "manifest.json").write_text(payload)
                    with self.assertRaises(AssertionError):
                        validate_snapshot(root)


if __name__ == "__main__":
    unittest.main()
