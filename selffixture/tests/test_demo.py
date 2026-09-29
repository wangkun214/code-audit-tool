# TODO: without validation of expr length
"""测试范围夹具 —— 用于验证 test 作用域分类（若测试目录未被引擎排除）。"""
import unittest


class Dummy(unittest.TestCase):
    def test_nothing(self):
        self.assertEqual(1, 1)


if __name__ == "__main__":
    unittest.main()
