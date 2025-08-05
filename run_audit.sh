#!/bin/bash
# 数据库审计工具启动脚本

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 切换到项目目录
cd "$SCRIPT_DIR"

# 激活虚拟环境
source "$SCRIPT_DIR/venv/bin/activate"

# 检查是否有参数
if [ $# -eq 0 ]; then
    echo "数据库敏感信息审计工具"
    echo "======================"
    echo ""
    echo "使用方法："
    echo "  ./run_audit.sh audit -c \"datasource_name,ip,port,username,password\""
    echo "  ./run_audit.sh audit -f config_file.txt    # 使用配置文件"
    echo "  ./run_audit.sh audit -i                    # 交互式配置"
    echo "  ./run_audit.sh audit --help                # 查看详细帮助"
    echo ""
    echo "配置文件示例："
    echo "  config/database_config.txt     # 本地数据库配置"
    echo "  config/production_config.txt   # 生产环境配置"
    echo "  config/test_config.txt         # 测试环境配置"
    echo "  config/config_template.txt     # 配置文件模板"
    echo ""
    echo "快速开始："
    echo "  ./run_audit.sh audit -f config/database_config.txt"
    exit 1
fi

# 运行审计工具
python3 main.py "$@"