#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
技术检测模块，用于识别网页使用的技术、框架和编程语言
"""

import re
import logging
import json
from urllib.parse import urlparse
from bs4 import BeautifulSoup

logger = logging.getLogger('xss_scanner')

class TechDetector:
    """网站技术检测类，用于识别网站使用的技术栈"""
    
    def __init__(self):
        """初始化技术检测器"""
        # 前端框架特征
        self.frontend_frameworks = {
            'React': [
                ('script', {'src': re.compile(r'react(-|\.min\.)?\.js')}),
                ('script', {'src': re.compile(r'react-dom(-|\.min\.)?\.js')}),
                ('meta', {'name': 'generator', 'content': re.compile(r'react', re.I)}),
                ('div', {'id': 'root'}),
                ('div', {'id': 'app'}),
                ('meta', {'name': 'next-head-count'}),
                ('code', {'id': '__NEXT_DATA__'})
            ],
            'Vue.js': [
                ('script', {'src': re.compile(r'vue(-|\.min\.)?\.js')}),
                ('div', {'id': 'app'}),
                ('div', {'id': 'vue-app'}),
                ('div', {'class': 'v-application'}),
                ('meta', {'name': 'generator', 'content': re.compile(r'vue', re.I)})
            ],
            'Angular': [
                ('script', {'src': re.compile(r'angular(-|\.min\.)?\.js')}),
                ('*', {'ng-app': re.compile(r'.*')}),
                ('*', {'ng-controller': re.compile(r'.*')}),
                ('*', {'ng-repeat': re.compile(r'.*')}),
                ('*', {'ng-bind': re.compile(r'.*')}),
                ('*', {'ng-model': re.compile(r'.*')})
            ],
            'jQuery': [
                ('script', {'src': re.compile(r'jquery(-|\.min\.)?\.js')}),
            ],
            'Bootstrap': [
                ('link', {'href': re.compile(r'bootstrap(-|\.min\.)?\.css')}),
                ('script', {'src': re.compile(r'bootstrap(-|\.min\.)?\.js')}),
                ('div', {'class': re.compile(r'container(-fluid)?')}),
                ('div', {'class': re.compile(r'row')}),
                ('div', {'class': re.compile(r'col(-[a-z]+-[0-9]+)?')})
            ]
        }
        
        # 后端框架和语言特征
        self.backend_technologies = {
            'PHP': [
                ('X-Powered-By', re.compile(r'PHP/?', re.I)),
                ('Set-Cookie', re.compile(r'PHPSESSID', re.I)),
                ('link', {'href': re.compile(r'\.php')}),
                ('a', {'href': re.compile(r'\.php')}),
                ('form', {'action': re.compile(r'\.php')})
            ],
            'WordPress': [
                ('meta', {'name': 'generator', 'content': re.compile(r'WordPress', re.I)}),
                ('link', {'href': re.compile(r'wp-content')}),
                ('script', {'src': re.compile(r'wp-includes')}),
                ('link', {'rel': 'https://api.w.org/'}),
                ('meta', {'property': 'og:site_name'}),
                ('body', {'class': re.compile(r'wordpress')})
            ],
            'Laravel': [
                ('input', {'name': '_token'}),
                ('meta', {'name': 'csrf-token'}),
                ('script', {'src': re.compile(r'vendor/laravel')}),
                ('Set-Cookie', re.compile(r'laravel_session', re.I))
            ],
            'Django': [
                ('input', {'name': 'csrfmiddlewaretoken'}),
                ('meta', {'name': 'csrf-token'}),
                ('X-Frame-Options', 'SAMEORIGIN')
            ],
            'Flask': [
                ('form', {'action': re.compile(r'\/[a-z0-9_]+\/?')}),
                ('Set-Cookie', re.compile(r'session=', re.I))
            ],
            'Python': [
                ('Server', re.compile(r'(Python|Werkzeug|Django|Tornado|Flask|CherryPy)', re.I)),
                ('X-Powered-By', re.compile(r'(Python|Werkzeug|Django|Tornado|Flask|CherryPy)', re.I))
            ],
            'ASP.NET': [
                ('X-Powered-By', re.compile(r'ASP\.NET', re.I)),
                ('X-AspNet-Version', re.compile(r'.*')),
                ('Set-Cookie', re.compile(r'ASP\.NET_SessionId', re.I)),
                ('form', {'action': re.compile(r'\.aspx')}),
                ('input', {'name': '__VIEWSTATE'})
            ],
            'Node.js': [
                ('X-Powered-By', re.compile(r'Express', re.I)),
                ('Set-Cookie', re.compile(r'connect\.sid', re.I))
            ],
            'Ruby on Rails': [
                ('X-Powered-By', re.compile(r'Phusion Passenger|Ruby|Rails', re.I)),
                ('Set-Cookie', re.compile(r'_session_id', re.I)),
                ('meta', {'name': 'csrf-param', 'content': 'authenticity_token'})
            ],
            'Java': [
                ('X-Powered-By', re.compile(r'(JSP|Servlet|Tomcat|JBoss|GlassFish|WebLogic|WebSphere|Jetty)', re.I)),
                ('Server', re.compile(r'(Tomcat|JBoss|GlassFish|WebLogic|WebSphere|Jetty)', re.I)),
                ('Set-Cookie', re.compile(r'JSESSIONID', re.I))
            ],
            'Go': [
                ('Server', re.compile(r'(go httpserver)', re.I)),
                ('X-Powered-By', re.compile(r'(go|gin|echo)', re.I))
            ]
        }
        
        # 服务器特征
        self.server_technologies = {
            'Nginx': [
                ('Server', re.compile(r'nginx', re.I))
            ],
            'Apache': [
                ('Server', re.compile(r'apache', re.I))
            ],
            'IIS': [
                ('Server', re.compile(r'IIS', re.I))
            ],
            'LiteSpeed': [
                ('Server', re.compile(r'LiteSpeed', re.I))
            ],
            'Cloudflare': [
                ('Server', re.compile(r'cloudflare', re.I)),
                ('CF-RAY', re.compile(r'.*')),
                ('CF-Cache-Status', re.compile(r'.*'))
            ],
            'Varnish': [
                ('X-Varnish', re.compile(r'.*')),
                ('X-Varnish-Cache', re.compile(r'.*'))
            ]
        }
        
        # WAF特征
        self.waf_technologies = {
            'Cloudflare': [
                ('Server', re.compile(r'cloudflare', re.I)),
                ('CF-RAY', re.compile(r'.*'))
            ],
            'ModSecurity': [
                ('Server', re.compile(r'mod_security', re.I)),
                ('X-Mod-Security', re.compile(r'.*'))
            ],
            'Sucuri': [
                ('X-Sucuri-ID', re.compile(r'.*')),
                ('X-Sucuri-Cache', re.compile(r'.*'))
            ],
            'Imperva': [
                ('X-Iinfo', re.compile(r'.*')),
                ('Set-Cookie', re.compile(r'incap_ses', re.I))
            ],
            'Akamai': [
                ('X-Akamai-Transformed', re.compile(r'.*')),
                ('Set-Cookie', re.compile(r'ak_bmsc', re.I))
            ],
            'F5 BIG-IP': [
                ('Set-Cookie', re.compile(r'BIGipServer', re.I)),
                ('Server', re.compile(r'BigIP', re.I))
            ],
            'Barracuda': [
                ('Set-Cookie', re.compile(r'barra_counter_session', re.I))
            ]
        }
        
    def detect(self, response, content=None):
        """
        检测网页使用的技术
        
        Args:
            response: HTTP响应对象
            content: HTML内容(可选)
            
        Returns:
            dict: 检测到的技术信息
        """
        if not response:
            return {}
            
        results = {
            'frontend': [],
            'backend': [],
            'server': [],
            'waf': []
        }
        
        # 提取HTML内容
        html_content = content or response.text
        
        # 解析HTML
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
        except Exception as e:
            logger.error(f"解析HTML时发生错误: {str(e)}")
            soup = None
        
        # 检测前端框架
        if soup:
            for framework, patterns in self.frontend_frameworks.items():
                for tag_name, attrs in patterns:
                    elements = soup.find_all(tag_name, attrs)
                    if elements:
                        if framework not in results['frontend']:
                            results['frontend'].append(framework)
                            break
        
        # 检测后端技术
        headers = response.headers
        
        # 基于HTTP头的检测
        for tech, patterns in self.backend_technologies.items():
            for header_name, pattern in patterns:
                if header_name in headers:
                    if isinstance(pattern, re.Pattern) and pattern.search(headers[header_name]):
                        if tech not in results['backend']:
                            results['backend'].append(tech)
                            break
        
        # 基于HTML的后端技术检测
        if soup:
            for tech, patterns in self.backend_technologies.items():
                if tech in results['backend']:
                    continue
                    
                for tag_name, attrs in patterns:
                    if tag_name in ['link', 'a', 'form', 'input', 'meta', 'script', 'body']:
                        elements = soup.find_all(tag_name, attrs)
                        if elements:
                            if tech not in results['backend']:
                                results['backend'].append(tech)
                                break
        
        # 检测服务器技术
        for server, patterns in self.server_technologies.items():
            for header_name, pattern in patterns:
                if header_name in headers:
                    if isinstance(pattern, re.Pattern) and pattern.search(headers[header_name]):
                        if server not in results['server']:
                            results['server'].append(server)
                            break
        
        # 检测WAF
        for waf, patterns in self.waf_technologies.items():
            for header_name, pattern in patterns:
                if header_name in headers:
                    if isinstance(pattern, re.Pattern) and pattern.search(headers[header_name]):
                        if waf not in results['waf']:
                            results['waf'].append(waf)
                            break
                            
        # 添加详细检测信息
        self._enhance_detection(results, soup, headers)
        
        return results
    
    def _enhance_detection(self, results, soup, headers):
        """
        增强检测，添加更多详细信息
        
        Args:
            results: 已检测的结果
            soup: BeautifulSoup对象
            headers: HTTP响应头
        """
        # 检测JavaScript库的版本
        if soup:
            # 检测React版本
            if 'React' in results['frontend']:
                script_tags = soup.find_all('script')
                for script in script_tags:
                    if script.string and 'React.version' in script.string:
                        version_match = re.search(r'React.version\s*=\s*[\'"]([^\'"]+)[\'"]', script.string)
                        if version_match:
                            results['frontend'].remove('React')
                            results['frontend'].append(f"React {version_match.group(1)}")
                            break
            
            # 检测Angular版本
            if 'Angular' in results['frontend']:
                for script in soup.find_all('script'):
                    if script.string and 'angular.version' in script.string:
                        version_match = re.search(r'angular.version\s*=\s*\{[^\}]*full:\s*[\'"]([^\'"]+)[\'"]', script.string)
                        if version_match:
                            results['frontend'].remove('Angular')
                            results['frontend'].append(f"Angular {version_match.group(1)}")
                            break
            
            # WordPress版本
            if 'WordPress' in results['backend']:
                meta_tags = soup.find_all('meta', {'name': 'generator'})
                for meta in meta_tags:
                    content = meta.get('content', '')
                    if 'WordPress' in content:
                        version_match = re.search(r'WordPress\s*([0-9\.]+)', content)
                        if version_match:
                            results['backend'].remove('WordPress')
                            results['backend'].append(f"WordPress {version_match.group(1)}")
                            break
        
        # 检测服务器版本
        if 'Server' in headers:
            server_header = headers['Server']
            
            # Nginx版本
            if 'Nginx' in results['server']:
                version_match = re.search(r'nginx/([0-9\.]+)', server_header, re.I)
                if version_match:
                    results['server'].remove('Nginx')
                    results['server'].append(f"Nginx {version_match.group(1)}")
            
            # Apache版本
            elif 'Apache' in results['server']:
                version_match = re.search(r'Apache/([0-9\.]+)', server_header, re.I)
                if version_match:
                    results['server'].remove('Apache')
                    results['server'].append(f"Apache {version_match.group(1)}")
    
    def get_waf_bypass_techniques(self, detected_waf):
        """
        根据检测到的WAF，返回可能的绕过技术
        
        Args:
            detected_waf: 检测到的WAF列表
            
        Returns:
            dict: WAF绕过技术
        """
        bypass_techniques = {}
        
        for waf in detected_waf:
            if waf == 'Cloudflare':
                bypass_techniques['Cloudflare'] = [
                    '使用不同的编码方式: HTML, URL, Unicode, Base64等',
                    '利用换行符分割XSS Payload',
                    '使用JavaScript事件处理程序的大小写混合形式',
                    '使用不同的HTML标签（避免常见的如script, img, iframe）',
                    '尝试使用较少被检测的事件如onmouseover, onerror, onwheel等'
                ]
            elif waf == 'ModSecurity':
                bypass_techniques['ModSecurity'] = [
                    '使用JavaScript事件处理程序的不同形式',
                    '使用HTML实体编码',
                    '分割Payload: < s c r i p t >',
                    '使用JavaScript的eval函数和字符串操作函数',
                    '使用CSS注入配合XSS'
                ]
            elif waf == 'Imperva':
                bypass_techniques['Imperva'] = [
                    '使用JavaScript原型链污染技术',
                    '避免使用关键词(alert, document.cookie等)',
                    '使用JavaScript的间接调用方法',
                    '使用多层编码: URL编码 + HTML编码 + Unicode编码',
                    '利用长字符串和重复字符迷惑WAF规则'
                ]
            elif waf == 'F5 BIG-IP':
                bypass_techniques['F5 BIG-IP'] = [
                    '使用非标准事件处理程序',
                    'DOM XSS手法通常更能绕过F5的防护',
                    '使用JavaScript模板字符串',
                    '使用JavaScript的Function构造函数',
                    '利用特定浏览器的解析差异'
                ]
            elif waf == 'Akamai':
                bypass_techniques['Akamai'] = [
                    '利用JavaScript的变量和函数名混淆',
                    '使用CDATA和注释规避特征检测',
                    '避免直接使用javascript:伪协议',
                    '使用data:text/html;base64,...编码',
                    '利用JavaScript中的字符串拼接和动态执行'
                ]
        
        return bypass_techniques 