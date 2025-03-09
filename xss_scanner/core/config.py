#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
配置模块，负责管理扫描器的配置参数
"""

import os
import json
import logging
from urllib.parse import urlparse

logger = logging.getLogger('xss_scanner')

class Config:
    """配置类，管理扫描器的所有配置选项"""
    
    def __init__(self):
        """初始化默认配置"""
        # 常规选项
        self.url = None
        self.depth = 2
        self.threads = 5
        self.timeout = 10
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        self.cookies = {}
        self.headers = {}
        self.proxy = None
        self.scan_level = 2
        self.scan_type = 'all'
        self.payload_level = 2
        self.output_file = None
        self.output_format = 'html'
        self.verbose = False
        self.no_color = False
        
        # 高级选项
        self.use_browser = False
        self.exploit = False
        self.custom_payloads = None
        self.exclude_pattern = None
        self.include_pattern = None
        self.auth = None
        
        # 内部使用
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.project_root = os.path.dirname(self.base_dir)
        
        # 优先检查项目根目录下的payloads目录，如果不存在再使用模块内部的payloads目录
        self.payloads_dir = os.path.join(self.project_root, 'payloads')
        if not os.path.exists(self.payloads_dir) or not os.path.isdir(self.payloads_dir):
            self.payloads_dir = os.path.join(self.base_dir, 'payloads')
            logger.debug(f"使用模块内部payloads目录: {self.payloads_dir}")
        else:
            logger.debug(f"使用项目根目录payloads目录: {self.payloads_dir}")
    
    def load_from_args(self, args):
        """
        从命令行参数加载配置
        
        Args:
            args: 解析后的命令行参数
        """
        # 常规选项
        if hasattr(args, 'url') and args.url:
            self.url = args.url
            
        if hasattr(args, 'depth') and args.depth is not None:
            self.depth = args.depth
            
        if hasattr(args, 'threads') and args.threads is not None:
            self.threads = args.threads
            
        if hasattr(args, 'timeout') and args.timeout is not None:
            self.timeout = args.timeout
            
        if hasattr(args, 'user_agent') and args.user_agent:
            self.user_agent = args.user_agent
            
        if hasattr(args, 'cookie') and args.cookie:
            self._parse_cookies(args.cookie)
            
        if hasattr(args, 'headers') and args.headers:
            self._parse_headers(args.headers)
            
        if hasattr(args, 'proxy') and args.proxy:
            self.proxy = args.proxy
            
        if hasattr(args, 'scan_level') and args.scan_level is not None:
            self.scan_level = args.scan_level
            
        if hasattr(args, 'scan_type') and args.scan_type:
            self.scan_type = args.scan_type
            
        if hasattr(args, 'payload_level') and args.payload_level is not None:
            self.payload_level = args.payload_level
            
        if hasattr(args, 'output') and args.output:
            self.output_file = args.output
            
        if hasattr(args, 'format') and args.format:
            self.output_format = args.format
            
        if hasattr(args, 'verbose'):
            self.verbose = args.verbose
            
        if hasattr(args, 'no_color'):
            self.no_color = args.no_color
        
        # 高级选项
        if hasattr(args, 'browser'):
            self.use_browser = args.browser
            
        if hasattr(args, 'exploit'):
            self.exploit = args.exploit
            
        if hasattr(args, 'custom_payloads') and args.custom_payloads:
            self.custom_payloads = args.custom_payloads
            
        if hasattr(args, 'exclude') and args.exclude:
            self.exclude_pattern = args.exclude
            
        if hasattr(args, 'include') and args.include:
            self.include_pattern = args.include
            
        if hasattr(args, 'auth') and args.auth:
            self._parse_auth(args.auth)
    
    def load_from_file(self, config_file):
        """
        从配置文件加载配置
        
        Args:
            config_file: 配置文件路径
        """
        if not os.path.exists(config_file):
            logger.error(f"配置文件不存在: {config_file}")
            return False
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            # 常规选项
            if 'url' in config_data:
                self.url = config_data['url']
                
            if 'depth' in config_data:
                self.depth = config_data['depth']
                
            if 'threads' in config_data:
                self.threads = config_data['threads']
                
            if 'timeout' in config_data:
                self.timeout = config_data['timeout']
                
            if 'user_agent' in config_data:
                self.user_agent = config_data['user_agent']
                
            if 'cookies' in config_data:
                self.cookies = config_data['cookies']
                
            if 'headers' in config_data:
                self.headers = config_data['headers']
                
            if 'proxy' in config_data:
                self.proxy = config_data['proxy']
                
            if 'scan_level' in config_data:
                self.scan_level = config_data['scan_level']
                
            if 'scan_type' in config_data:
                self.scan_type = config_data['scan_type']
                
            if 'payload_level' in config_data:
                self.payload_level = config_data['payload_level']
                
            if 'output_file' in config_data:
                self.output_file = config_data['output_file']
                
            if 'output_format' in config_data:
                self.output_format = config_data['output_format']
                
            if 'verbose' in config_data:
                self.verbose = config_data['verbose']
                
            if 'no_color' in config_data:
                self.no_color = config_data['no_color']
            
            # 高级选项
            if 'use_browser' in config_data:
                self.use_browser = config_data['use_browser']
                
            if 'exploit' in config_data:
                self.exploit = config_data['exploit']
                
            if 'custom_payloads' in config_data:
                self.custom_payloads = config_data['custom_payloads']
                
            if 'exclude_pattern' in config_data:
                self.exclude_pattern = config_data['exclude_pattern']
                
            if 'include_pattern' in config_data:
                self.include_pattern = config_data['include_pattern']
                
            if 'auth' in config_data:
                self.auth = config_data['auth']
            
            logger.info(f"成功从 {config_file} 加载配置")
            return True
        except Exception as e:
            logger.error(f"加载配置文件时出错: {str(e)}")
            return False
    
    def save_to_file(self, config_file):
        """
        将配置保存到文件
        
        Args:
            config_file: 配置文件路径
            
        Returns:
            bool: 是否成功保存
        """
        config_data = {
            # 常规选项
            'url': self.url,
            'depth': self.depth,
            'threads': self.threads,
            'timeout': self.timeout,
            'user_agent': self.user_agent,
            'cookies': self.cookies,
            'headers': self.headers,
            'proxy': self.proxy,
            'scan_level': self.scan_level,
            'scan_type': self.scan_type,
            'payload_level': self.payload_level,
            'output_file': self.output_file,
            'output_format': self.output_format,
            'verbose': self.verbose,
            'no_color': self.no_color,
            
            # 高级选项
            'use_browser': self.use_browser,
            'exploit': self.exploit,
            'custom_payloads': self.custom_payloads,
            'exclude_pattern': self.exclude_pattern,
            'include_pattern': self.include_pattern,
            'auth': self.auth
        }
        
        try:
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=4)
            
            logger.info(f"配置已保存到 {config_file}")
            return True
        except Exception as e:
            logger.error(f"保存配置文件时出错: {str(e)}")
            return False
    
    def _parse_cookies(self, cookie_str):
        """
        解析Cookie字符串
        
        Args:
            cookie_str: Cookie字符串，格式为"name=value; name2=value2"
        """
        if not cookie_str:
            return
            
        try:
            cookies = {}
            for cookie in cookie_str.split(';'):
                if '=' in cookie:
                    name, value = cookie.strip().split('=', 1)
                    cookies[name] = value
            
            self.cookies = cookies
        except Exception as e:
            logger.error(f"解析Cookie时出错: {str(e)}")
    
    def _parse_headers(self, headers_str):
        """
        解析HTTP头字符串
        
        Args:
            headers_str: HTTP头字符串，格式为"Header1:Value1;Header2:Value2"
        """
        if not headers_str:
            return
            
        try:
            headers = {}
            for header in headers_str.split(';'):
                if ':' in header:
                    name, value = header.strip().split(':', 1)
                    headers[name] = value
            
            self.headers = headers
        except Exception as e:
            logger.error(f"解析HTTP头时出错: {str(e)}")
    
    def _parse_auth(self, auth_str):
        """
        解析基本认证字符串
        
        Args:
            auth_str: 基本认证字符串，格式为"username:password"
        """
        if not auth_str:
            return
            
        try:
            if ':' in auth_str:
                username, password = auth_str.split(':', 1)
                self.auth = {
                    'username': username,
                    'password': password
                }
        except Exception as e:
            logger.error(f"解析认证信息时出错: {str(e)}")
    
    def get_payloads_file(self, payload_type):
        """
        获取有效载荷文件路径
        
        Args:
            payload_type: 有效载荷类型，如'xss'、'sqli'
            
        Returns:
            str: 有效载荷文件路径，如果文件不存在则返回None
        """
        if self.custom_payloads and os.path.exists(self.custom_payloads):
            logger.info(f"使用自定义有效载荷文件: {self.custom_payloads}")
            return self.custom_payloads
        
        # 尝试多个位置查找有效载荷文件
        payload_paths = []
        
        # 构建可能的文件名
        level_filename = f"{payload_type}_level{self.payload_level}.txt"
        waf_bypass_filename = f"{payload_type}_waf_bypass.txt"
        level1_filename = f"{payload_type}_level1.txt"
        
        # 首先检查项目根目录下的payloads目录
        root_payload_dir = os.path.join(self.project_root, 'payloads')
        if os.path.exists(root_payload_dir) and os.path.isdir(root_payload_dir):
            level_path = os.path.join(root_payload_dir, payload_type, level_filename)
            waf_path = os.path.join(root_payload_dir, payload_type, waf_bypass_filename)
            level1_path = os.path.join(root_payload_dir, payload_type, level1_filename)
            
            payload_paths.append(level_path)
            # 尝试特殊的WAF绕过有效载荷
            if self.payload_level >= 2:
                payload_paths.append(waf_path)
            # 始终包含level1作为后备
            payload_paths.append(level1_path)
        
        # 然后检查模块内部的payloads目录
        module_payload_dir = os.path.join(self.base_dir, 'payloads')
        if os.path.exists(module_payload_dir) and os.path.isdir(module_payload_dir):
            level_path = os.path.join(module_payload_dir, payload_type, level_filename)
            waf_path = os.path.join(module_payload_dir, payload_type, waf_bypass_filename)
            level1_path = os.path.join(module_payload_dir, payload_type, level1_filename)
            
            payload_paths.append(level_path)
            # 尝试特殊的WAF绕过有效载荷
            if self.payload_level >= 2:
                payload_paths.append(waf_path)
            # 始终包含level1作为后备
            payload_paths.append(level1_path)
        
        # 尝试各个路径，返回第一个存在的文件
        found_file = None
        for path in payload_paths:
            if os.path.exists(path) and os.path.isfile(path):
                logger.debug(f"找到有效载荷文件: {path}")
                found_file = path
                break
        
        if not found_file:
            logger.warning(f"找不到类型为 {payload_type} 级别为 {self.payload_level} 的有效载荷文件")
            logger.warning(f"尝试搜索的路径: {', '.join(payload_paths)}")
            
            # 尝试使用任何可用的有效载荷文件
            for path in payload_paths:
                if os.path.exists(path) and os.path.isfile(path):
                    logger.info(f"使用替代的有效载荷文件: {path}")
                    return path
            
            # 如果仍然找不到，最后一搏：尝试root目录下的任何级别
            root_payload_type_dir = os.path.join(root_payload_dir, payload_type)
            if os.path.exists(root_payload_type_dir) and os.path.isdir(root_payload_type_dir):
                for file in os.listdir(root_payload_type_dir):
                    if file.endswith('.txt'):
                        path = os.path.join(root_payload_type_dir, file)
                        logger.info(f"使用最终备选的有效载荷文件: {path}")
                        return path
            
            # 真的找不到了
            logger.error(f"没有找到任何适用于{payload_type}的有效载荷文件")
            return None
        
        return found_file 