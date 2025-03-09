#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
命令行界面模块，负责显示扫描器的交互界面
"""

import os
import sys
import time
import logging
from datetime import datetime

# 定义颜色代码
COLORS = {
    'RED': '\033[91m',
    'GREEN': '\033[92m',
    'YELLOW': '\033[93m',
    'BLUE': '\033[94m',
    'PURPLE': '\033[95m',
    'CYAN': '\033[96m',
    'WHITE': '\033[97m',
    'BOLD': '\033[1m',
    'UNDERLINE': '\033[4m',
    'RESET': '\033[0m'
}

def colored(text, color):
    """
    为文本添加颜色
    
    Args:
        text: 文本内容
        color: 颜色名称
        
    Returns:
        str: 带颜色的文本
    """
    if color not in COLORS:
        return text
    return f"{COLORS[color]}{text}{COLORS['RESET']}"

def display_banner():
    """显示扫描器的Banner"""
    banner = f"""
{colored('='*80, 'CYAN')}
{colored('    __  _____ ___     ___                              ', 'CYAN')}
{colored('    \\ \\/ / __/ __|   / __|__ _ _ _  _ _  ___ _ _      ', 'CYAN')}
{colored('     >  <\\__ \\__ \\  | (__/ _` | \' \\| \' \\/ -_) \'_|    ', 'CYAN')}
{colored('    /_/\\_\\___/___/   \\___\\__,_|_||_|_||_\\___|_|       ', 'CYAN')}
{colored('                                                       ', 'CYAN')}
{colored('='*80, 'CYAN')}
{colored('    XSS深度漏洞扫描器 v1.0.0                          ', 'CYAN')}
{colored('    作者: Lucifrix                           ', 'CYAN')}
{colored('    支持的漏洞类型: XSS, CSRF, SQL注入, LFI, RFI, SSRF, XXE', 'CYAN')}
{colored('='*80, 'CYAN')}
"""
    print(banner)

def display_progress(current, total, message="正在扫描", width=50):
    """
    显示进度条
    
    Args:
        current: 当前进度
        total: 总进度
        message: 显示的消息
        width: 进度条宽度
    """
    # 避免除以零
    if total == 0:
        total = 1
        
    # 计算进度百分比
    percent = current / total
    completed = int(width * percent)
    remaining = width - completed
    
    # 构建进度条
    progress_bar = f"[{colored('#' * completed, 'GREEN')}{' ' * remaining}] {int(percent * 100)}%"
    
    # 显示进度条
    sys.stdout.write(f"\r{message}: {progress_bar}")
    sys.stdout.flush()
    
    # 如果完成，则换行
    if current == total:
        sys.stdout.write("\n")

def display_results(results, total_time):
    """
    显示扫描结果
    
    Args:
        results: 扫描结果列表
        total_time: 总耗时
    """
    # 合并所有结果的统计信息
    total_stats = {
        'pages_scanned': 0,
        'forms_tested': 0,
        'parameters_tested': 0,
        'vulnerabilities_found': 0
    }
    
    all_vulnerabilities = []
    
    for result in results:
        # 更新统计信息
        for key in total_stats:
            if key in result['statistics']:
                total_stats[key] += result['statistics'][key]
        
        # 收集所有漏洞
        all_vulnerabilities.extend(result['vulnerabilities'])
    
    # 显示统计信息
    print(f"\n{colored('='*80, 'CYAN')}")
    print(f"{colored('扫描统计信息:', 'CYAN')}")
    print(f"{colored('='*80, 'CYAN')}")
    print(f"总耗时: {total_time:.2f}秒")
    print(f"扫描页面数: {total_stats['pages_scanned']}")
    print(f"测试表单数: {total_stats['forms_tested']}")
    print(f"测试参数数: {total_stats['parameters_tested']}")
    print(f"发现漏洞数: {colored(str(total_stats['vulnerabilities_found']), 'RED' if total_stats['vulnerabilities_found'] > 0 else 'GREEN')}")
    
    # 如果有漏洞，则显示漏洞详情
    if all_vulnerabilities:
        print(f"\n{colored('='*80, 'RED')}")
        print(f"{colored('漏洞详情:', 'RED')}")
        print(f"{colored('='*80, 'RED')}")
        
        # 按漏洞类型分组
        vuln_by_type = {}
        for vuln in all_vulnerabilities:
            vuln_type = vuln['type']
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)
        
        # 显示各类漏洞详情
        for vuln_type, vulns in vuln_by_type.items():
            print(f"\n{colored(f'● {vuln_type} 漏洞 ({len(vulns)}个):', 'YELLOW')}")
            
            for i, vuln in enumerate(vulns, 1):
                print(f"\n  {colored(f'#{i}', 'BOLD')} {colored(vuln['url'], 'UNDERLINE')}")
                print(f"  - {colored('风险等级:', 'BOLD')} {colored(vuln['severity'], 'RED' if vuln['severity'] == '高' else 'YELLOW' if vuln['severity'] == '中' else 'GREEN')}")
                print(f"  - {colored('描述:', 'BOLD')} {vuln['description']}")
                
                if 'parameter' in vuln:
                    print(f"  - {colored('参数:', 'BOLD')} {vuln['parameter']}")
                    
                if 'payload' in vuln:
                    print(f"  - {colored('Payload:', 'BOLD')} {vuln['payload']}")
                    
                if 'details' in vuln:
                    print(f"  - {colored('详情:', 'BOLD')} {vuln['details']}")
                    
                if 'exploit_result' in vuln:
                    print(f"  - {colored('利用结果:', 'BOLD')} {vuln['exploit_result']['description']}")
                    
                if 'recommendation' in vuln:
                    print(f"  - {colored('修复建议:', 'BOLD')} {vuln['recommendation']}")
    else:
        print(f"\n{colored('='*80, 'GREEN')}")
        print(f"{colored('恭喜! 未发现漏洞。', 'GREEN')}")
        print(f"{colored('='*80, 'GREEN')}")
        
    print(f"\n{colored('扫描完成!', 'CYAN')}")
    print(f"{colored('='*80, 'CYAN')}")

def display_vulnerability(vuln):
    """
    显示单个漏洞的详细信息
    
    Args:
        vuln: 漏洞信息
    """
    print(f"\n{colored('='*80, 'RED')}")
    print(f"{colored('漏洞详情:', 'RED')}")
    print(f"{colored('='*80, 'RED')}")
    
    print(f"URL: {colored(vuln['url'], 'UNDERLINE')}")
    print(f"类型: {colored(vuln['type'], 'YELLOW')}")
    print(f"风险等级: {colored(vuln['severity'], 'RED' if vuln['severity'] == '高' else 'YELLOW' if vuln['severity'] == '中' else 'GREEN')}")
    print(f"描述: {vuln['description']}")
    
    if 'parameter' in vuln:
        print(f"参数: {vuln['parameter']}")
        
    if 'payload' in vuln:
        print(f"Payload: {vuln['payload']}")
        
    if 'details' in vuln:
        print(f"详情: {vuln['details']}")
        
    if 'exploit_result' in vuln:
        print(f"利用结果: {vuln['exploit_result']['description']}")
        
    if 'recommendation' in vuln:
        print(f"修复建议: {vuln['recommendation']}")
        
    print(f"{colored('='*80, 'RED')}")

def prompt_yes_no(message):
    """
    提示用户输入是/否
    
    Args:
        message: 提示消息
        
    Returns:
        bool: 用户选择是返回True，否返回False
    """
    valid_responses = {
        'y': True, 'yes': True, '是': True, 
        'n': False, 'no': False, '否': False
    }
    
    while True:
        response = input(f"{message} (y/n): ").lower()
        if response in valid_responses:
            return valid_responses[response]
        print("请输入 'y' 或 'n'")

def prompt_input(message, default=None):
    """
    提示用户输入
    
    Args:
        message: 提示消息
        default: 默认值
        
    Returns:
        str: 用户输入
    """
    if default:
        prompt = f"{message} [{default}]: "
    else:
        prompt = f"{message}: "
        
    response = input(prompt)
    
    # 如果用户没有输入，则使用默认值
    if not response and default is not None:
        return default
        
    return response 