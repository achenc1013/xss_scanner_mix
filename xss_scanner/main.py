#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
XSS 深度漏洞扫描器
作者: 高级渗透工程师
版本: 1.0.0
描述: 一个全面的XSS漏洞扫描工具，能够扫描多种平台的XSS漏洞，并提供其他漏洞的辅助扫描功能
"""

import sys
import os
import argparse
import time
import logging
from datetime import datetime

# 导入内部模块
from xss_scanner.core.scanner_engine import ScannerEngine
from xss_scanner.core.config import Config
from xss_scanner.core.logger import setup_logger
from xss_scanner.ui.cli import display_banner, display_progress, display_results
from xss_scanner.utils.validator import validate_target

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='XSS 深度漏洞扫描器')
    parser.add_argument('-u', '--url', help='目标URL')
    parser.add_argument('-f', '--file', help='包含目标URL的文件')
    parser.add_argument('-d', '--depth', type=int, default=2, help='爬虫深度 (默认: 2)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='线程数 (默认: 5)')
    parser.add_argument('--timeout', type=int, default=10, help='请求超时时间，单位秒 (默认: 10)')
    parser.add_argument('--user-agent', help='自定义User-Agent')
    parser.add_argument('--cookie', help='请求Cookie')
    parser.add_argument('--headers', help='自定义HTTP头，格式: "Header1:Value1;Header2:Value2"')
    parser.add_argument('--proxy', help='HTTP代理，格式: http://user:pass@host:port')
    parser.add_argument('--scan-level', type=int, choices=[1, 2, 3], default=2, 
                        help='扫描级别: 1-快速, 2-标准, 3-深度 (默认: 2)')
    parser.add_argument('--scan-type', choices=['all', 'xss', 'csrf', 'sqli', 'lfi', 'rfi', 'ssrf', 'xxe'], 
                        default='all', help='扫描类型 (默认: all)')
    parser.add_argument('--payload-level', type=int, choices=[1, 2, 3], default=2,
                        help='Payload复杂度: 1-基础, 2-标准, 3-高级 (默认: 2)')
    parser.add_argument('-o', '--output', help='输出报告文件路径')
    parser.add_argument('--format', choices=['txt', 'html', 'json', 'xml'], default='html',
                        help='报告输出格式 (默认: html)')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细输出')
    parser.add_argument('--no-color', action='store_true', help='禁用彩色输出')
    
    # 高级选项
    advanced_group = parser.add_argument_group('高级选项')
    advanced_group.add_argument('--browser', action='store_true', help='使用真实浏览器进行扫描')
    advanced_group.add_argument('--exploit', action='store_true', help='尝试利用发现的漏洞')
    advanced_group.add_argument('--custom-payloads', help='自定义Payload文件路径')
    advanced_group.add_argument('--exclude', help='排除URL模式 (正则表达式)')
    advanced_group.add_argument('--include', help='仅包含URL模式 (正则表达式)')
    advanced_group.add_argument('--auth', help='基本认证，格式: username:password')
    
    return parser.parse_args()

def main():
    """主函数"""
    # 显示Banner
    display_banner()
    
    # 解析命令行参数
    args = parse_arguments()
    
    # 配置日志
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = setup_logger(log_level, args.no_color)
    
    # 配置扫描器
    config = Config()
    config.load_from_args(args)
    
    # 验证目标
    targets = []
    if args.url:
        if validate_target(args.url):
            targets.append(args.url)
        else:
            logger.error(f"无效的目标URL: {args.url}")
            sys.exit(1)
    elif args.file:
        if not os.path.exists(args.file):
            logger.error(f"文件不存在: {args.file}")
            sys.exit(1)
        with open(args.file, 'r') as f:
            for line in f:
                url = line.strip()
                if validate_target(url):
                    targets.append(url)
    else:
        logger.error("必须指定目标URL(-u)或包含目标的文件(-f)")
        sys.exit(1)
    
    if not targets:
        logger.error("没有有效的目标")
        sys.exit(1)
    
    # 初始化扫描引擎
    scanner = ScannerEngine(config)
    
    # 开始扫描
    start_time = time.time()
    logger.info(f"扫描开始，目标数量: {len(targets)}")
    
    results = []
    for target in targets:
        logger.info(f"正在扫描: {target}")
        result = scanner.scan(target)
        results.append(result)
        
    total_time = time.time() - start_time
    
    # 显示结果
    display_results(results, total_time)
    
    # 生成报告
    if args.output:
        from xss_scanner.reporters.report_generator import generate_report
        generate_report(results, args.output, args.format)
        logger.info(f"报告已保存至: {args.output}")
    
    logger.info(f"扫描完成，总耗时: {total_time:.2f}秒")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n用户中断，扫描已停止")
        sys.exit(0)
    except Exception as e:
        print(f"发生错误: {str(e)}")
        sys.exit(1) 