#!/bin/bash
# brtech-fusion/package.sh
cd $(dirname "$0") || exit

echo "开始构建 brtech-fusion 底座通用包..."

# 1. 清理旧产物
rm -rf build/ dist/ *.egg-info

# 2. 构建 Wheel (Any 平台)
# --wheel 参数确保只生成 .whl 文件，不生成源码包 .tar.gz（保护源码意识）
python -m build --wheel

# 3. 验证
if [ -f dist/*-none-any.whl ]; then
    echo "打包成功！产物位置: $(ls dist/*-none-any.whl)"
else
    echo "打包失败，请检查配置。"
    exit 1
fi