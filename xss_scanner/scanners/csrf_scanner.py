#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CSRF扫描器模块，负责扫描CSRF漏洞
"""

import re
import logging
import random
import string
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

logger = logging.getLogger('xss_scanner')

class CSRFScanner:
    """CSRF扫描器类，负责扫描CSRF漏洞"""
    
    def __init__(self, http_client):
        """
        初始化CSRF扫描器
        
        Args:
            http_client: HTTP客户端对象
        """
        self.http_client = http_client
        
        # 敏感操作关键词
        self.sensitive_keywords = [
            'user', 'account', 'profile', 'password', 'email', 'settings',
            'admin', 'create', 'delete', 'remove', 'update', 'edit', 'modify',
            'register', 'signup', 'login', 'logout', 'authenticate', 'auth',
            'transfer', 'payment', 'pay', 'fund', 'money', 'order', 'checkout',
            'purchase', 'buy', 'shop', 'cart', 'add', 'submit', 'confirm',
            'upload', 'download', 'send', 'message', 'post', 'comment', 'reply',
            'subscribe', 'unsubscribe', 'membership', 'join', 'leave'
        ]
        
        # CSRF令牌常见名称
        self.csrf_token_names = [
            'csrf', 'xsrf', 'token', '_token', 'authenticity_token',
            'csrf_token', 'xsrf_token', 'security_token', 'request_token',
            'csrf-token', 'xsrf-token', 'anti-csrf', 'anti-xsrf',
            '__RequestVerificationToken', '_csrf', '_xsrf', 'csrfmiddlewaretoken'
        ]
    
    def scan_form(self, url, form, field=None):
        """
        扫描表单中的CSRF漏洞
        
        Args:
            url: 页面URL
            form: 表单信息
            field: 表单字段（对CSRF扫描不需要）
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        # 如果是GET方法表单，则不检查CSRF
        if form['method'].upper() == 'GET':
            return None
            
        # 检查表单是否包含敏感操作关键词
        form_action = form['action'].lower()
        form_is_sensitive = any(keyword in form_action for keyword in self.sensitive_keywords)
        
        # 检查表单字段名称是否包含敏感关键词
        for field in form.get('fields', []):
            if field.get('name') and any(keyword in field['name'].lower() for keyword in self.sensitive_keywords):
                form_is_sensitive = True
                break
                
        # 如果表单不包含敏感操作，则不检查CSRF
        if not form_is_sensitive:
            return None
            
        logger.debug(f"扫描CSRF: {form['action']} @ {url}")
        
        # 检查表单是否包含CSRF令牌
        has_csrf_token = False
        token_field = None
        
        for field in form.get('fields', []):
            field_name = field.get('name', '').lower()
            
            # 检查字段名称是否匹配CSRF令牌常见名称
            if any(token_name in field_name for token_name in self.csrf_token_names):
                has_csrf_token = True
                token_field = field['name']
                break
                
        # 如果表单包含CSRF令牌，则需要进一步验证
        if has_csrf_token:
            # 再次请求页面，验证CSRF令牌是否会改变
            try:
                token_value1 = self._get_csrf_token_value(url, token_field)
                token_value2 = self._get_csrf_token_value(url, token_field)
                
                # 如果两次请求的令牌值相同，则可能存在CSRF漏洞
                if token_value1 == token_value2:
                    # 生成表单的唯一标识
                    form_id = f"{form.get('id', '')}-{form['action']}"
                    return {
                        'type': 'CSRF',
                        'url': url,
                        'form_id': form_id,
                        'parameter': token_field,
                        'description': '表单中的CSRF令牌值在多次请求中保持不变，可能存在CSRF漏洞',
                        'severity': 'Medium',
                        'details': {
                            'form_action': form['action'],
                            'token_field': token_field,
                            'token_value': token_value1
                        }
                    }
            except Exception as e:
                logger.error(f"验证CSRF令牌时出错: {str(e)}")
        else:
            # 如果表单不包含CSRF令牌，则存在CSRF漏洞
            # 生成表单的唯一标识
            form_id = f"{form.get('id', '')}-{form['action']}"
            return {
                'type': 'CSRF',
                'url': url,
                'form_id': form_id,
                'description': '表单缺少CSRF令牌，可能存在CSRF漏洞',
                'severity': 'High',
                'details': {
                    'form_action': form['action'],
                    'form_method': form['method']
                }
            }
            
        return None
    
    def scan_parameter(self, url, param):
        """
        扫描URL参数中的CSRF漏洞（不适用于参数扫描）
        
        Args:
            url: 页面URL
            param: 参数名
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        # CSRF漏洞通常与表单相关，不适用于URL参数扫描
        return None
    
    def _get_csrf_token_value(self, url, token_field):
        """
        获取页面中CSRF令牌的值
        
        Args:
            url: 页面URL
            token_field: 令牌字段名
            
        Returns:
            str: 令牌值，如果未找到则返回None
        """
        response = self.http_client.get(url)
        if not response:
            return None
            
        # 解析HTML
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 查找匹配的输入字段
            input_field = soup.find('input', {'name': token_field})
            if input_field and input_field.has_attr('value'):
                return input_field['value']
                
            # 查找匹配的meta标签
            meta_field = soup.find('meta', {'name': token_field})
            if meta_field and meta_field.has_attr('content'):
                return meta_field['content']
                
            # 查找匹配的JavaScript变量（简单实现，可能不适用于所有情况）
            script_tags = soup.find_all('script')
            for script in script_tags:
                if script.string and token_field in script.string:
                    # 简单的正则表达式匹配
                    match = re.search(f"{token_field}['\"]?\\s*[:=]\\s*['\"]([^'\"]+)['\"]", script.string)
                    if match:
                        return match.group(1)
        except Exception as e:
            logger.error(f"获取CSRF令牌时发生错误: {str(e)}")
            
        return None
    
    def can_scan_form(self):
        """是否可以扫描表单"""
        return True
    
    def can_scan_params(self):
        """是否可以扫描URL参数"""
        return False 