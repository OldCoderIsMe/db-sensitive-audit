# DB Sensitive Audit

一个强大的数据库敏感信息审计工具，用于自动检测和报告数据库中的敏感数据。

## 核心特性

- 🔍 **智能检测**: 支持手机号、身份证号、银行卡号等8种敏感信息类型
- ✅ **二次确认**: 对检测结果进行正则表达式验证，确保准确性
- 📊 **Excel报告**: 自动生成结构化的审计报告，支持超链接跳转
- ⚙️ **灵活配置**: 支持自定义检测规则和参数
- 🎯 **双重检测**: 字段名关键词 + 值格式匹配
- 🚫 **智能过滤**: 自动排除测试数据
- 🗄️ **多数据库支持**: 支持MySQL数据库连接和审计
- 👥 **用户权限分析**: 收集和分析数据库用户权限信息
- 📋 **智能数据抽样**: 随机抽取表数据进行敏感信息分析
- 💻 **命令行工具**: 支持多种运行方式（文件配置、命令行参数、交互式）
- 🔧 **可扩展架构**: 易于添加新的敏感信息类型和检测规则

## 适用场景

- 数据安全合规检查
- 敏感信息资产盘点  
- 数据库安全审计
- GDPR/网络安全法合规

## 技术栈

- Python 3.6+
- PyMySQL (MySQL连接)
- Pandas (数据处理)
- OpenPyXL (Excel导出)

## 安装

### 从源码安装

```bash
# 克隆项目
git clone https://github.com/yourusername/db-sensitive-audit.git
cd db-sensitive-audit

# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或者 venv\Scripts\activate  # Windows

# 安装依赖
pip install -r requirements.txt
```

## 快速开始

```bash
# 交互式审计（推荐新手）
python main.py audit -i

# 使用配置文件
python main.py audit -f config/database_config.txt

# 直接指定数据库
python main.py audit -c "prod_db,192.168.1.100,3306,admin,password"
```

## 使用方法

### 数据库审计

#### 1. 交互式配置（推荐新手使用）

```bash
python main.py audit -i
```

按提示输入数据库配置信息，格式：`datasource_name,ip,port,username,password`

#### 2. 使用配置文件

```bash
# 创建配置文件
cp example_config.txt my_config.txt
# 编辑配置文件，填入真实的数据库信息
# 然后运行审计
python main.py audit -f my_config.txt
```

#### 3. 命令行直接配置

```bash
python main.py audit -c "test_db,localhost,3306,root,password123"
```

#### 4. 自定义输出目录

```bash
python main.py audit -f config.txt -o /path/to/output
```

### 配置文件格式

配置文件每行一个数据源，格式如下：
```
# 注释行以#开头
datasource_name,ip,port,username,password
prod_mysql,192.168.1.100,3306,admin,admin123
dev_mysql,dev.example.com,3306,developer,dev_pass
```

### 输出说明

审计完成后，会在输出目录生成Excel文件，文件名格式：`{datasource_name}_{timestamp}.xlsx`

### Excel报告结构

每个Excel文件包含：

#### 🚨 审计结果 sheet
风险汇总总览，按风险等级排序：

| 列名 | 描述 | 示例 |
|------|------|------|
| **风险类型** | 风险分类 | `敏感信息` / `权限风险` |
| **风险等级** | 风险严重程度 | `高` / `中` / `低` (高风险红色背景，中风险黄色背景) |
| **检查项** | 相关检查对象 | `user_db` / `用户权限` (支持点击跳转到对应sheet) |
| **表名** | 相关数据表 | `user_info` |
| **字段名** | 相关字段 | `phone` |
| **敏感类型** | 检测到的敏感信息类型 | `手机号` / `数据库权限` |
| **风险描述** | 详细风险说明 | `表 user_info 的字段 phone 包含 手机号` |
| **检测值** | 发现的敏感数据样本 | `138****5678` |
| **记录总数** | 相关记录数量 | `1000` |
| **建议** | 修复建议 | `对包含手机号的字段进行加密或脱敏处理` |

#### 📋 用户权限 sheet
记录数据库用户及权限信息：
- 用户名
- 主机  
- 各项权限详情（查询、插入、更新、删除等，权限值为"是"时显示为红色加粗）

#### 📊 {dbname} sheet（每个业务数据库一个sheet）
每张表占一行，包含以下字段：

| 列名 | 描述 | 示例 |
|------|------|------|
| **表名** | 数据库表名 | `user_info` |
| **字段名和值** | JSON格式的字段名和随机抽样值 | `{"id": 1, "name": "张三", "phone": "13812345678"}` |
| **敏感信息** | 检测到的敏感信息详情（JSON格式） | `{"手机号": {"phone": {"value": "13812345678", "field_match": true, "value_match": true}}}` |
| **敏感信息确认** | 二次正则验证结果 | `是` / `否` (是时显示为红色加粗) |
| **总条数** | 该表的总记录数 | `1000` |

#### 🔍 敏感信息字段说明
- **field_match**: 字段名是否匹配敏感信息关键词
- **value_match**: 字段值是否匹配敏感信息正则表达式
- **value**: 检测到的敏感信息值（截断显示）

## 🔒 敏感信息检测

### 支持的敏感信息类型

| 类型 | 描述 | 字段名关键词 | 正则规则 |
|------|------|-------------|----------|
| 🔗 **手机号** | 中国手机号码（11位纯数字，1开头） | `phone`, `mobile`, `telephone` | `^1[3-9]\d{9}$` |
| 🪪 **身份证号** | 中国身份证号（18位或15位） | `id_card`, `identity`, `id_number` | 标准身份证格式验证 |
| 💳 **银行卡号** | 银行卡号码（13-20位数字） | `bank_card`, `card_number`, `account_no` | `^[1-9]\d{12,19}$` |
| 📧 **邮箱** | 电子邮箱地址 | `email`, `mail`, `e_mail` | 标准邮箱格式验证 |
| 💬 **QQ号** | QQ号码（5-11位数字） | `qq`, `qq_number`, `qq_no` | `^[1-9][0-9]{4,10}$` |
| 💚 **微信号** | 微信号（字母开头，6-20位） | `wechat`, `weixin`, `wx` | `^[a-zA-Z][a-zA-Z0-9_-]{5,19}$` |
| 🌐 **IP地址** | IPv4地址 | `ip`, `ip_addr`, `ip_address` | 标准IPv4格式验证 |
| 🖥️ **MAC地址** | MAC地址 | `mac`, `mac_addr`, `mac_address` | 标准MAC格式验证 |

### 🎯 检测机制

#### 1️⃣ 双重检测逻辑
- **字段名检测**: 根据字段名关键词识别（如：`phone`, `mobile`, `id_card`等）
- **值匹配检测**: 根据正则表达式匹配字段值
- **双重验证**: 字段名和值都匹配时置信度更高

#### 2️⃣ 敏感信息确认
**核心功能**: 对检测到的值进行二次正则验证，确保为真实敏感数据

**确认规则**:
- ✅ **"是"**: 检测到的值通过了严格的正则表达式验证，确认为真实敏感数据
- ❌ **"否"**: 检测到的值未通过正则验证，或只是字段名匹配但值不符合格式

**实际案例**:
```
✅ phone: "13812345678"        → 敏感信息确认: "是" (标准手机号格式)
❌ phone: "+86-138-1234-5678"  → 敏感信息确认: "否" (非纯数字格式)  
❌ phone: null                → 敏感信息确认: "否" (空值)
❌ id_card: "123456789"       → 敏感信息确认: "否" (无效身份证格式)
✅ email: "user@domain.com"   → 敏感信息确认: "是" (有效邮箱格式)
```

#### 3️⃣ 智能过滤
- **测试数据过滤**: 自动排除包含 `test`, `demo`, `example`, `sample`, `fake` 等关键词的数据
- **长度限制**: 跳过超长字段值（默认100字符）
- **格式验证**: 严格按照各类敏感信息的标准格式进行验证

### ⚙️ 自定义配置

#### 配置文件位置
- **敏感信息规则**: `config/sensitive_rules.json`
- **数据源配置**: `config/*.txt`

#### 可配置项目
通过修改 `config/sensitive_rules.json` 可以：

- 🔄 **启用/禁用检测类型**: 在 `enabled_rules` 中添加或移除规则
- 🏷️ **修改字段关键词**: 调整 `field_keywords` 数组
- 📝 **调整正则表达式**: 修改 `regex_patterns` 规则
- ➕ **添加自定义类型**: 新增自定义敏感信息类型
- ⚙️ **调整检测参数**: 配置大小写敏感、字段长度限制、测试数据过滤等

#### 配置示例
```json
{
  "sensitive_rules": {
    "自定义证件": {
      "field_keywords": ["cert", "certificate", "license"],
      "regex_patterns": ["^CERT\\d{8}$"],
      "description": "自定义证件号码"
    }
  },
  "settings": {
    "enabled_rules": ["手机号", "身份证号", "自定义证件"],
    "case_sensitive": false,
    "max_field_length": 100,
    "exclude_test_data": true
  }
}
```

📚 **详细配置说明**: 请参考 `config/README.md`

### 其他运行方式

#### 使用一键脚本（推荐）
```bash
# 使用配置文件
./run_audit.sh audit -f config/test_sensitive.txt

# 交互式配置
./run_audit.sh audit -i

# 查看帮助
./run_audit.sh audit --help
```

#### 模块方式运行

```bash
# 使用模块方式运行
python -m db_sensitive_audit.app audit -i

# 直接运行应用
python db_sensitive_audit/app.py audit --help
```

## 开发

### 运行测试

```bash
pytest
```

### 代码格式化

```bash
black .
```

### 代码检查

```bash
flake8
mypy .
```

### 安全检查

```bash
bandit -r .
safety check
```

## 🗂️ 项目结构

```
db-sensitive-audit/
├── 📁 main.py                      # 🚀 主入口文件
├── 📁 db_sensitive_audit/          # 📦 主包目录
│   ├── __init__.py                # 包初始化文件
│   ├── app.py                     # 🎯 应用程序主模块
│   └── database_auditor.py        # 🔍 核心审计引擎
├── 📁 config/                      # ⚙️ 配置文件目录
│   ├── sensitive_rules.json       # 🔒 敏感信息检测规则
│   ├── *.txt                      # 📋 数据源配置文件
│   └── README.md                  # 📚 配置说明文档
├── 📁 tests/                       # 🧪 测试目录
│   ├── test_app.py                # 应用测试
│   └── test_database_auditor.py   # 审计器测试
├── 📁 audit_reports/               # 📊 审计报告输出目录
├── 📁 logs/                        # 📝 日志文件目录
├── 📁 venv/                        # 🐍 Python虚拟环境
├── requirements.txt                # 📋 Python依赖文件
├── run_audit.sh                   # 🔧 快速运行脚本
└── README.md                      # 📖 项目说明文档
```

### 🔗 快速导航

- **核心模块**: `db_sensitive_audit/database_auditor.py` - 敏感信息检测引擎
- **配置管理**: `config/` - 所有配置文件和说明
- **运行脚本**: `run_audit.sh` - 一键运行审计
- **测试代码**: `tests/` - 完整的单元测试覆盖
- **输出目录**: `audit_reports/` - 生成的Excel报告
- **日志目录**: `logs/` - 运行日志和调试信息

## 📋 最佳实践

### 🔒 安全建议
- 🚫 **不要将包含真实密码的配置文件提交到版本控制系统**
- 🔐 **使用专用的审计账号，分配最小必要权限（只读权限）**
- 📝 **定期更新敏感信息检测规则，适应新的业务需求**
- 🗂️ **妥善保管生成的审计报告，避免敏感信息泄露**

### ⚡ 性能优化
- 🎯 **针对大型数据库，考虑分批处理或限制表数量**
- ⏰ **在业务低峰期运行审计，避免影响生产环境**
- 📊 **定期清理旧的审计报告，节省存储空间**

### 🛠️ 故障排除
- 📋 **检查日志文件** `logs/audit_YYYYMMDD.log` 获取详细错误信息
- 🔌 **确认数据库连接信息正确**，包括IP、端口、用户名、密码
- 📦 **验证Python依赖** 是否正确安装：`pip list`
- 🐍 **确认Python版本** 兼容性（支持Python 3.6+）

### 📈 扩展开发
- ➕ **添加新的敏感信息类型**：修改 `config/sensitive_rules.json`
- 🔍 **自定义检测逻辑**：扩展 `db_sensitive_audit/database_auditor.py`
- 📊 **支持新的数据库类型**：添加相应的连接器
- 🧪 **编写测试用例**：确保新功能的可靠性

## 🤝 贡献

欢迎提交Issue和Pull Request来改进这个项目！

## 许可证

MIT License