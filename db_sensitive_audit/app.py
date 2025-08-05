#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DB Sensitive Audit Application
数据库敏感信息审计应用程序
"""

import sys
import os
import argparse
from typing import List, Optional
from .database_auditor import DatabaseAuditor


class App:
    """主应用程序类"""
    
    def __init__(self):
        self.name = "DB Sensitive Audit"
        self.version = "1.0.0"
        self.auditor = DatabaseAuditor()
    
    def run(self, args: Optional[List[str]] = None) -> None:
        """运行应用程序
        
        Args:
            args: 命令行参数列表
        """
        print(f"{self.name} v{self.version}")
        print("数据库敏感信息审计工具")
        print("=" * 50)
        
        if not args:
            self.show_help()
            return
        
        parser = self.create_parser()
        try:
            parsed_args = parser.parse_args(args)
            self.handle_command(parsed_args)
        except SystemExit:
            pass
    
    def create_parser(self) -> argparse.ArgumentParser:
        """创建命令行参数解析器"""
        parser = argparse.ArgumentParser(
            description="数据库敏感信息审计工具",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
使用示例:
  # 从配置文件审计
  python -m checker.app audit -f config.txt
  
  # 从命令行参数审计
  python -m checker.app audit -c "db1,localhost,3306,root,password"
  
  # 交互式输入配置
  python -m checker.app audit -i
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='可用命令')
        
        # audit 命令
        audit_parser = subparsers.add_parser('audit', help='执行数据库审计')
        audit_group = audit_parser.add_mutually_exclusive_group(required=True)
        audit_group.add_argument('-f', '--file', help='配置文件路径')
        audit_group.add_argument('-c', '--config', help='配置字符串')
        audit_group.add_argument('-i', '--interactive', action='store_true', help='交互式输入')
        audit_parser.add_argument('-o', '--output', default='audit_reports', help='输出目录 (默认: audit_reports)')
        
        return parser
    
    def show_help(self) -> None:
        """显示帮助信息"""
        print("使用方法:")
        print("  python -m checker.app audit [选项]")
        print("")
        print("选项:")
        print("  -f, --file FILE       从文件读取配置")
        print("  -c, --config CONFIG   直接提供配置字符串")
        print("  -i, --interactive     交互式输入配置")
        print("  -o, --output DIR      输出目录 (默认: audit_reports)")
        print("")
        print("配置格式:")
        print("  datasource_name,ip,port,username,password")
        print("  每行一个数据源，使用逗号分隔")
        print("")
        print("示例:")
        print("  python -m checker.app audit -c \"test_db,localhost,3306,root,123456\"")
    
    def handle_command(self, args) -> None:
        """处理命令"""
        if args.command == 'audit':
            self.handle_audit_command(args)
        else:
            print("未知命令，请使用 --help 查看帮助")
    
    def handle_audit_command(self, args) -> None:
        """处理审计命令"""
        config_text = ""
        
        if args.file:
            # 从文件读取配置
            if not os.path.exists(args.file):
                print(f"错误: 配置文件不存在: {args.file}")
                return
            
            try:
                with open(args.file, 'r', encoding='utf-8') as f:
                    config_text = f.read()
                print(f"从文件读取配置: {args.file}")
            except Exception as e:
                print(f"错误: 读取配置文件失败: {str(e)}")
                return
        
        elif args.config:
            # 直接使用配置字符串
            config_text = args.config
            print("使用命令行配置")
        
        elif args.interactive:
            # 交互式输入
            config_text = self.get_interactive_config()
        
        if not config_text.strip():
            print("错误: 配置为空")
            return
        
        # 设置输出目录
        self.auditor.output_dir = args.output
        self.auditor.ensure_output_dir()
        
        # 执行审计
        print(f"开始执行数据库审计...")
        print(f"输出目录: {args.output}")
        print("-" * 50)
        
        try:
            excel_files = self.auditor.audit_multiple_datasources(config_text)
            
            print("\n" + "=" * 50)
            print("审计完成！")
            print(f"生成了 {len(excel_files)} 个Excel报告:")
            for file_path in excel_files:
                print(f"  📊 {file_path}")
            
            if excel_files:
                print(f"\n所有报告保存在目录: {args.output}")
            else:
                print("\n⚠️  没有成功生成任何报告，请检查配置和网络连接")
                
        except Exception as e:
            print(f"错误: 审计过程中发生异常: {str(e)}")
    
    def get_interactive_config(self) -> str:
        """交互式获取配置"""
        print("\n交互式配置模式")
        print("请按照格式输入数据源配置: datasource_name,ip,port,username,password")
        print("输入空行结束配置")
        print("-" * 50)
        
        config_lines = []
        line_number = 1
        
        while True:
            try:
                line = input(f"数据源 {line_number}: ").strip()
                if not line:
                    break
                
                # 简单验证格式
                parts = line.split(',')
                if len(parts) < 5:
                    print("  ⚠️  格式错误，请确保包含5个字段")
                    continue
                
                config_lines.append(line)
                line_number += 1
                print(f"  ✓ 已添加: {parts[0]}")
                
            except KeyboardInterrupt:
                print("\n\n操作已取消")
                return ""
        
        return '\n'.join(config_lines)
    
    def check_security(self) -> bool:
        """执行安全检查
        
        Returns:
            bool: 检查是否通过
        """
        print("正在执行安全检查...")
        # TODO: 实现具体的安全检查逻辑
        return True


def main():
    """主函数"""
    app = App()
    app.run(sys.argv[1:] if len(sys.argv) > 1 else None)


if __name__ == "__main__":
    main()