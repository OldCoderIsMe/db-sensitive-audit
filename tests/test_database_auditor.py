#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test cases for the DatabaseAuditor module
"""

import pytest
import sys
import os
import tempfile
from unittest.mock import Mock, patch, MagicMock

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db_sensitive_audit.database_auditor import DatabaseAuditor


class TestDatabaseAuditor:
    """DatabaseAuditor类的测试用例"""
    
    def setup_method(self):
        """每个测试方法前执行"""
        self.auditor = DatabaseAuditor()
    
    def test_auditor_initialization(self):
        """测试审计器初始化"""
        assert self.auditor.output_dir == "audit_reports"
    
    def test_parse_datasource_config(self):
        """测试解析数据源配置"""
        config_text = """
# 注释行
test_db1,localhost,3306,root,password
test_db2,192.168.1.100,3306,admin,admin123

# 另一个注释
test_db3,test.com,3306,user,pass123
        """
        
        datasources = self.auditor.parse_datasource_config(config_text)
        
        assert len(datasources) == 3
        assert datasources[0]['datasource_name'] == 'test_db1'
        assert datasources[0]['ip'] == 'localhost'
        assert datasources[0]['port'] == 3306
        assert datasources[0]['username'] == 'root'
        assert datasources[0]['password'] == 'password'
    
    def test_parse_invalid_config(self):
        """测试解析无效配置"""
        config_text = """
invalid_line_without_enough_parts
another,invalid,line
        """
        
        datasources = self.auditor.parse_datasource_config(config_text)
        assert len(datasources) == 0
    
    def test_ensure_output_dir(self):
        """测试确保输出目录存在"""
        with tempfile.TemporaryDirectory() as temp_dir:
            test_output_dir = os.path.join(temp_dir, "test_output")
            self.auditor.output_dir = test_output_dir
            
            # 目录不存在
            assert not os.path.exists(test_output_dir)
            
            # 调用ensure_output_dir
            self.auditor.ensure_output_dir()
            
            # 目录应该被创建
            assert os.path.exists(test_output_dir)
    
    @patch('pymysql.connect')
    def test_connect_database_success(self, mock_connect):
        """测试成功连接数据库"""
        mock_connection = Mock()
        mock_connect.return_value = mock_connection
        
        datasource = {
            'datasource_name': 'test_db',
            'ip': 'localhost',
            'port': 3306,
            'username': 'root',
            'password': 'password'
        }
        
        connection = self.auditor.connect_database(datasource)
        
        assert connection == mock_connection
        mock_connect.assert_called_once_with(
            host='localhost',
            port=3306,
            user='root',
            password='password',
            charset='utf8mb4',
            connect_timeout=10,
            read_timeout=30,
            write_timeout=30
        )
    
    @patch('pymysql.connect')
    def test_connect_database_failure(self, mock_connect):
        """测试连接数据库失败"""
        mock_connect.side_effect = Exception("Connection failed")
        
        datasource = {
            'datasource_name': 'test_db',
            'ip': 'localhost',
            'port': 3306,
            'username': 'root',
            'password': 'wrong_password'
        }
        
        connection = self.auditor.connect_database(datasource)
        
        assert connection is None
    
    def test_get_database_users(self):
        """测试获取数据库用户信息"""
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_connection.cursor.return_value = mock_cursor
        mock_cursor.__enter__ = Mock(return_value=mock_cursor)
        mock_cursor.__exit__ = Mock(return_value=None)
        
        # 模拟查询结果
        mock_cursor.description = [
            ('用户名',), ('主机',), ('查询权限',), ('插入权限',)
        ]
        mock_cursor.fetchall.return_value = [
            ('root', 'localhost', 'Y', 'Y'),
            ('user1', '%', 'Y', 'N')
        ]
        
        users = self.auditor.get_database_users(mock_connection)
        
        assert len(users) == 2
        assert users[0]['用户名'] == 'root'
        assert users[0]['查询权限'] == '是'
        assert users[1]['插入权限'] == '否'
    
    def test_get_databases(self):
        """测试获取数据库列表"""
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_connection.cursor.return_value = mock_cursor
        mock_cursor.__enter__ = Mock(return_value=mock_cursor)
        mock_cursor.__exit__ = Mock(return_value=None)
        
        # 模拟SHOW DATABASES结果
        mock_cursor.fetchall.return_value = [
            ('information_schema',),
            ('mysql',),
            ('performance_schema',),
            ('sys',),
            ('business_db1',),
            ('business_db2',)
        ]
        
        databases = self.auditor.get_databases(mock_connection)
        
        # 应该过滤掉系统数据库
        assert len(databases) == 2
        assert 'business_db1' in databases
        assert 'business_db2' in databases
        assert 'mysql' not in databases
    
    def test_get_table_info(self):
        """测试获取表信息"""
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_connection.cursor.return_value = mock_cursor
        mock_cursor.__enter__ = Mock(return_value=mock_cursor)
        mock_cursor.__exit__ = Mock(return_value=None)
        
        # 模拟SHOW TABLES结果
        mock_cursor.fetchall.side_effect = [
            [('table1',), ('table2',)],  # SHOW TABLES
            [('id',), ('name',), ('phone',)],  # DESCRIBE table1 (包含phone字段)
            [('id',), ('title',)],  # DESCRIBE table2
        ]
        
        # 模拟fetchone结果
        mock_cursor.fetchone.side_effect = [
            (100,),  # COUNT(*) table1
            (1, 'John', '13812345678'),  # SELECT * FROM table1 LIMIT 1 OFFSET x (包含手机号)
            (0,)  # COUNT(*) table2 (空表)
        ]
        
        table_info = self.auditor.get_table_info(mock_connection, 'test_db')
        
        # 现在每张表一条记录
        assert len(table_info) == 2
        
        # 检查table1的记录
        table1_record = next((info for info in table_info if info['表名'] == 'table1'), None)
        assert table1_record is not None
        assert table1_record['总条数'] == 100
        # 检查JSON格式的字段名和值
        import json
        field_values = json.loads(table1_record['字段名和值'])
        assert 'id' in field_values
        assert 'name' in field_values
        assert 'phone' in field_values
        assert field_values['id'] == 1
        assert field_values['name'] == 'John'
        assert field_values['phone'] == '13812345678'
        
        # 检查敏感信息识别
        sensitive_info = json.loads(table1_record['敏感信息'])
        assert '手机号' in sensitive_info  # 应该识别出手机号
        phone_data = sensitive_info['手机号']
        assert 'phone' in phone_data  # 字段名包含phone
        assert phone_data['phone']['value'] == '13812345678'  # 值是手机号
        
        # 检查敏感信息确认
        assert '敏感信息确认' in table1_record
        assert table1_record['敏感信息确认'] == '是'  # 因为手机号格式正确
        
        # 检查table2的记录（空表）
        table2_record = next((info for info in table_info if info['表名'] == 'table2'), None)
        assert table2_record is not None
        assert table2_record['总条数'] == 0
        # 空表应该显示字段结构
        field_values = json.loads(table2_record['字段名和值'])
        assert 'id' in field_values
        assert 'title' in field_values
        assert field_values['id'] is None
        assert field_values['title'] is None
        
        # 空表的敏感信息字段应该为空JSON
        sensitive_info = json.loads(table2_record['敏感信息'])
        assert sensitive_info == {}  # 没有敏感信息相关字段
        
        # 空表的敏感信息确认应该是"否"
        assert table2_record['敏感信息确认'] == '否'
    
    def test_identify_sensitive_info(self):
        """测试敏感信息识别功能"""
        columns = ['id', 'name', 'phone', 'id_card', 'email', 'bank_card']
        
        # 测试包含多种敏感信息的记录
        record = (1, 'John', '13812345678', '110101199001011234', 'john@domain.com', '6222021234567890123')
        sensitive_info = self.auditor.identify_sensitive_info(columns, record)
        
        # 验证手机号识别
        assert '手机号' in sensitive_info
        phone_data = sensitive_info['手机号']
        assert 'phone' in phone_data
        assert phone_data['phone']['value'] == '13812345678'
        assert phone_data['phone']['field_match'] == True
        assert phone_data['phone']['value_match'] == True
        
        # 验证身份证号识别
        assert '身份证号' in sensitive_info
        id_card_data = sensitive_info['身份证号']
        assert 'id_card' in id_card_data
        assert id_card_data['id_card']['value'] == '110101199001011234'
        
        # 验证银行卡号识别
        assert '银行卡号' in sensitive_info
        bank_card_data = sensitive_info['银行卡号']
        assert 'bank_card' in bank_card_data
        assert bank_card_data['bank_card']['value'] == '6222021234567890123'
        
        # 测试空记录
        empty_record = ()
        empty_result = self.auditor.identify_sensitive_info(columns, empty_record)
        assert empty_result == {}
        
        # 测试只有值匹配但字段名不匹配的情况
        columns2 = ['id', 'name', 'some_field']
        record2 = (2, 'Bob', '13912345678')  # some_field的值是中国手机号
        result2 = self.auditor.identify_sensitive_info(columns2, record2)
        
        # 应该识别出值匹配的手机号
        assert '手机号' in result2
        assert 'some_field' in result2['手机号']
        assert result2['手机号']['some_field']['value'] == '13912345678'
        assert result2['手机号']['some_field']['field_match'] == False
        assert result2['手机号']['some_field']['value_match'] == True
        
        # 测试无效格式不被识别
        columns3 = ['id', 'phone', 'id_card']
        record3 = (3, '+8613912345678', '123456789')  # 无效格式
        result3 = self.auditor.identify_sensitive_info(columns3, record3)
        
        # 手机号：字段名匹配但值不匹配
        assert '手机号' in result3
        assert 'phone' in result3['手机号']
        assert result3['手机号']['phone']['field_match'] == True
        assert result3['手机号']['phone']['value_match'] == False
        
        # 身份证号：字段名匹配但值不匹配
        assert '身份证号' in result3
        assert 'id_card' in result3['身份证号']
        assert result3['身份证号']['id_card']['field_match'] == True
        assert result3['身份证号']['id_card']['value_match'] == False

    def test_confirm_sensitive_data(self):
        """测试敏感信息确认功能"""
        # 测试真实敏感数据确认
        real_sensitive_info = {
            '手机号': {
                'phone': {
                    'value': '13812345678',
                    'field_match': True,
                    'value_match': True
                }
            },
            '身份证号': {
                'id_card': {
                    'value': '110101199001011234',
                    'field_match': True,
                    'value_match': True
                }
            }
        }
        result = self.auditor.confirm_sensitive_data(real_sensitive_info)
        assert result == '是'
        
        # 测试假敏感数据确认
        fake_sensitive_info = {
            '手机号': {
                'phone': {
                    'value': '+8613812345678',  # 不是纯数字格式
                    'field_match': True,
                    'value_match': False
                }
            }
        }
        result = self.auditor.confirm_sensitive_data(fake_sensitive_info)
        assert result == '否'
        
        # 测试空敏感信息
        empty_sensitive_info = {}
        result = self.auditor.confirm_sensitive_data(empty_sensitive_info)
        assert result == '否'
        
        # 测试只有字段匹配但值不匹配的情况
        field_only_info = {
            '身份证号': {
                'id_card': {
                    'value': '123456789',  # 无效身份证号
                    'field_match': True,
                    'value_match': False
                }
            }
        }
        result = self.auditor.confirm_sensitive_data(field_only_info)
        assert result == '否'
    
    def test_generate_audit_summary(self):
        """测试审计结果汇总生成"""
        # 准备测试数据
        users = [
            {
                '用户名': 'root',
                '主机': '%',
                '查询权限': '是',
                '超级权限': '是',
                '文件权限': '是'
            },
            {
                '用户名': 'app_user',
                '主机': 'localhost',
                '查询权限': '是',
                '插入权限': '是'
            }
        ]
        
        databases_info = {
            'test_db': [
                {
                    '表名': 'users',
                    '字段名和值': '{"phone": "13812345678"}',
                    '敏感信息': '{"手机号": {"phone": {"value": "13812345678", "field_match": true, "value_match": true}}}',
                    '敏感信息确认': '是',
                    '总条数': 100
                },
                {
                    '表名': 'logs',
                    '字段名和值': '{"message": "test"}',
                    '敏感信息': '{}',
                    '敏感信息确认': '否',
                    '总条数': 50
                }
            ]
        }
        
        # 生成审计结果
        audit_results = self.auditor._generate_audit_summary(users, databases_info)
        
        # 验证结果
        assert len(audit_results) > 0
        
        # 检查是否包含敏感信息风险
        sensitive_risks = [r for r in audit_results if r['风险类型'] == '敏感信息']
        assert len(sensitive_risks) == 1
        assert '手机号' in sensitive_risks[0]['敏感类型']
        assert sensitive_risks[0]['风险等级'] == '高'
        assert sensitive_risks[0]['检查项'] == 'test_db'
        
        # 检查是否包含权限风险
        permission_risks = [r for r in audit_results if r['风险类型'] == '权限风险']
        assert len(permission_risks) > 0
        
        # 验证高危权限识别
        high_risk_users = [r for r in permission_risks if '超级权限' in r['风险描述']]
        assert len(high_risk_users) == 1
        assert high_risk_users[0]['风险等级'] == '高'
        assert high_risk_users[0]['检查项'] == '用户权限'
        
        # 验证通配符主机权限识别
        wildcard_risks = [r for r in permission_risks if '任意主机' in r['风险描述']]
        assert len(wildcard_risks) == 1
        assert wildcard_risks[0]['风险等级'] == '中'
        assert wildcard_risks[0]['检查项'] == '用户权限'


if __name__ == "__main__":
    pytest.main([__file__])