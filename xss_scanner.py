#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
XSS深度漏洞扫描器 - 主入口脚本
"""

import os
import sys

# 添加当前目录到Python路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 导入主模块
from xss_scanner.main import main

if __name__ == "__main__":
    # 调用主函数
    main() 