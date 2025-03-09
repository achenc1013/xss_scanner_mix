#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
参数验证模块，负责验证用户输入的参数
"""

import re
import os
import logging
from urllib.parse import urlparse

logger = logging.getLogger('xss_scanner')

def validate_target(target):
    """
    验证目标URL是否有效
    
    Args:
        target: 目标URL
        
    Returns:
        bool: 是否有效
    """
    if not target:
        return False
        
    # 检查URL格式
    if not target.startswith(('http://', 'https://')):
        logger.warning(f"无效的URL格式: {target}，URL必须以http://或https://开头")
        return False
        
    # 解析URL
    try:
        parsed_url = urlparse(target)
        if not parsed_url.netloc:
            logger.warning(f"无效的URL: {target}，缺少域名")
            return False
    except Exception as e:
        logger.warning(f"URL解析失败: {target} - {str(e)}")
        return False
        
    return True

def validate_file_path(file_path, check_exists=True, check_write=False):
    """
    验证文件路径是否有效
    
    Args:
        file_path: 文件路径
        check_exists: 是否检查文件是否存在
        check_write: 是否检查文件是否可写
        
    Returns:
        bool: 是否有效
    """
    if not file_path:
        return False
        
    # 检查文件是否存在
    if check_exists and not os.path.exists(file_path):
        logger.warning(f"文件不存在: {file_path}")
        return False
        
    # 检查文件是否可写
    if check_write:
        try:
            # 检查文件是否可写
            if os.path.exists(file_path):
                if not os.access(file_path, os.W_OK):
                    logger.warning(f"文件不可写: {file_path}")
                    return False
            else:
                # 检查目录是否可写
                dir_path = os.path.dirname(file_path)
                if dir_path and not os.access(dir_path, os.W_OK):
                    logger.warning(f"目录不可写: {dir_path}")
                    return False
        except Exception as e:
            logger.warning(f"检查文件权限失败: {file_path} - {str(e)}")
            return False
            
    return True

def validate_ip(ip):
    """
    验证IP地址是否有效
    
    Args:
        ip: IP地址
        
    Returns:
        bool: 是否有效
    """
    if not ip:
        return False
        
    # IPv4正则表达式
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    
    # 检查格式
    if not re.match(ipv4_pattern, ip):
        return False
        
    # 检查每个段的范围
    segments = ip.split('.')
    for segment in segments:
        if not 0 <= int(segment) <= 255:
            return False
            
    return True

def validate_port(port):
    """
    验证端口号是否有效
    
    Args:
        port: 端口号
        
    Returns:
        bool: 是否有效
    """
    try:
        port = int(port)
        return 1 <= port <= 65535
    except:
        return False

def validate_proxy(proxy):
    """
    验证代理设置是否有效
    
    Args:
        proxy: 代理设置
        
    Returns:
        bool: 是否有效
    """
    if not proxy:
        return False
        
    # 检查代理格式
    if not proxy.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
        logger.warning(f"无效的代理格式: {proxy}，代理必须以http://、https://、socks4://或socks5://开头")
        return False
        
    # 解析代理
    try:
        parsed_proxy = urlparse(proxy)
        if not parsed_proxy.netloc:
            logger.warning(f"无效的代理: {proxy}，缺少主机名")
            return False
    except Exception as e:
        logger.warning(f"代理解析失败: {proxy} - {str(e)}")
        return False
        
    return True

def validate_regex(pattern):
    """
    验证正则表达式是否有效
    
    Args:
        pattern: 正则表达式
        
    Returns:
        bool: 是否有效
    """
    if not pattern:
        return False
        
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False

def validate_headers(headers):
    """
    验证HTTP头是否有效
    
    Args:
        headers: HTTP头，格式：Header1:Value1;Header2:Value2
        
    Returns:
        bool: 是否有效
    """
    if not headers:
        return False
        
    try:
        # 分割HTTP头
        header_pairs = headers.split(';')
        for header in header_pairs:
            if header.strip() and ':' not in header:
                logger.warning(f"无效的HTTP头格式: {header}，应为Header:Value格式")
                return False
                
        return True
    except Exception as e:
        logger.warning(f"验证HTTP头失败: {str(e)}")
        return False

def validate_cookies(cookies):
    """
    验证Cookie是否有效
    
    Args:
        cookies: Cookie，格式：name1=value1; name2=value2
        
    Returns:
        bool: 是否有效
    """
    if not cookies:
        return False
        
    try:
        # 分割Cookie
        cookie_pairs = cookies.split(';')
        for cookie in cookie_pairs:
            if cookie.strip() and '=' not in cookie:
                logger.warning(f"无效的Cookie格式: {cookie}，应为name=value格式")
                return False
                
        return True
    except Exception as e:
        logger.warning(f"验证Cookie失败: {str(e)}")
        return False 