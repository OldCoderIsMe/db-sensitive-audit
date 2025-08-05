#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test cases for the App module
"""

import pytest
import sys
import os

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db_sensitive_audit.app import App


class TestApp:
    """App类的测试用例"""
    
    def test_app_initialization(self):
        """测试App类的初始化"""
        app = App()
        assert app.name == "DB Sensitive Audit"
        assert app.version == "1.0.0"
    
    def test_check_security(self):
        """测试安全检查功能"""
        app = App()
        result = app.check_security()
        assert result is True
    
    def test_run_without_args(self):
        """测试无参数运行"""
        app = App()
        # 这个测试主要确保不会抛出异常
        try:
            app.run()
            assert True
        except Exception as e:
            pytest.fail(f"run() 方法抛出了异常: {e}")
    
    def test_run_with_args(self):
        """测试带参数运行"""
        app = App()
        args = ["test", "argument"]
        try:
            app.run(args)
            assert True
        except Exception as e:
            pytest.fail(f"run() 方法抛出了异常: {e}")


if __name__ == "__main__":
    pytest.main([__file__])