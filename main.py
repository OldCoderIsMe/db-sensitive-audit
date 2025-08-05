#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DB Sensitive Audit
数据库敏感信息审计工具
"""

import sys
from db_sensitive_audit.app import main as app_main


def main():
    """主函数"""
    print("欢迎使用数据库敏感信息审计工具！")
    print("=" * 50)
    
    if len(sys.argv) == 1:
        print("使用方法:")
        print("  python main.py audit [选项]")
        print("")
        print("获取详细帮助:")
        print("  python main.py audit --help")
        print("")
        print("快速开始:")
        print("  python main.py audit -i    # 交互式配置")
        return
    
    # 直接调用app的main函数
    app_main()


if __name__ == "__main__":
    main()