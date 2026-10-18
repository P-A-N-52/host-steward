import re
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]


class RoutingTests(unittest.TestCase):
    """文档路由契约：SKILL.md 与 design.md §3 结构树必须与 guidance/ 实际文件一致。"""

    def test_skill_routes_and_guidance_files_match(self):
        skill = (PROJECT / "SKILL.md").read_text(encoding="utf-8")
        routed = set(re.findall(r"\]\((guidance/[^)\s#]+\.md)(?:#[^)\s]*)?\)", skill))
        self.assertTrue(routed, "SKILL.md 未路由任何 guidance 文件")
        actual = {"guidance/" + path.relative_to(PROJECT / "guidance").as_posix()
                  for path in (PROJECT / "guidance").rglob("*.md")}
        dangling = routed - actual
        unrouted = actual - routed
        self.assertFalse(dangling, f"SKILL.md 路由指向不存在的指导文件：{sorted(dangling)}")
        self.assertFalse(unrouted, f"guidance/ 存在未被 SKILL.md 路由引用的文件：{sorted(unrouted)}")

    def test_design_structure_tree_lists_every_guidance_file(self):
        design = (PROJECT / "design.md").read_text(encoding="utf-8")
        block = re.search(r"建议结构：\n\n```text\n(.*?)```", design, re.DOTALL)
        self.assertIsNotNone(block, "design.md §3 缺少指导结构树")
        listed = set(re.findall(r"([\w.-]+\.md)", block.group(1)))
        actual = [path.name for path in (PROJECT / "guidance").rglob("*.md")]
        self.assertEqual(len(actual), len(set(actual)),
                         "guidance/ 出现同名文件，结构树按文件名比对已不适用，需改为相对路径比对")
        self.assertEqual(listed, set(actual), "design.md §3 结构树与 guidance/ 实际文件不一致")


if __name__ == "__main__":
    unittest.main()
