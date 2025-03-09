#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
HTTP客户端模块，负责发送HTTP请求
"""

import logging
import requests
import random
import time
from urllib.parse import urlparse, urljoin
from requests.exceptions import RequestException, Timeout, ConnectionError
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 禁用不安全请求的警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger('xss_scanner')

class HttpClient:
    """HTTP客户端类，负责处理HTTP请求"""
    
    def __init__(self, timeout=10, user_agent=None, proxy=None, cookies=None, headers=None, verify_ssl=False):
        """
        初始化HTTP客户端
        
        Args:
            timeout: 请求超时时间
            user_agent: 用户代理
            proxy: 代理
            cookies: Cookies
            headers: 自定义HTTP头
            verify_ssl: 是否验证SSL证书
        """
        self.timeout = timeout
        self.user_agent = user_agent
        self.proxy = proxy
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        
        # 设置默认User-Agent
        if not self.user_agent:
            self.user_agent = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/91.0.4472.124 Safari/537.36"
            )
            
        # 设置默认请求头
        if 'User-Agent' not in self.headers:
            self.headers['User-Agent'] = self.user_agent
            
    def get(self, url, params=None, headers=None, cookies=None, allow_redirects=True, timeout=None):
        """
        发送GET请求
        
        Args:
            url: 请求的URL
            params: 请求参数
            headers: 请求头
            cookies: Cookies
            allow_redirects: 是否允许重定向
            timeout: 超时时间
            
        Returns:
            requests.Response: 响应对象
        """
        merged_headers = self._merge_headers(headers)
        merged_cookies = self._merge_cookies(cookies)
        timeout = timeout or self.timeout
        
        try:
            response = self.session.get(
                url=url,
                params=params,
                headers=merged_headers,
                cookies=merged_cookies,
                proxies=self._get_proxies(),
                allow_redirects=allow_redirects,
                timeout=timeout,
                verify=self.verify_ssl
            )
            return response
        except Timeout:
            logger.warning(f"请求超时: {url}")
        except ConnectionError:
            logger.warning(f"连接错误: {url}")
        except RequestException as e:
            logger.warning(f"请求异常: {url} - {str(e)}")
        except Exception as e:
            logger.error(f"发送GET请求时发生错误: {url} - {str(e)}")
            
        return None
        
    def post(self, url, data=None, json=None, headers=None, cookies=None, allow_redirects=True, timeout=None):
        """
        发送POST请求
        
        Args:
            url: 请求的URL
            data: 表单数据
            json: JSON数据
            headers: 请求头
            cookies: Cookies
            allow_redirects: 是否允许重定向
            timeout: 超时时间
            
        Returns:
            requests.Response: 响应对象
        """
        merged_headers = self._merge_headers(headers)
        merged_cookies = self._merge_cookies(cookies)
        timeout = timeout or self.timeout
        
        try:
            response = self.session.post(
                url=url,
                data=data,
                json=json,
                headers=merged_headers,
                cookies=merged_cookies,
                proxies=self._get_proxies(),
                allow_redirects=allow_redirects,
                timeout=timeout,
                verify=self.verify_ssl
            )
            return response
        except Timeout:
            logger.warning(f"请求超时: {url}")
        except ConnectionError:
            logger.warning(f"连接错误: {url}")
        except RequestException as e:
            logger.warning(f"请求异常: {url} - {str(e)}")
        except Exception as e:
            logger.error(f"发送POST请求时发生错误: {url} - {str(e)}")
            
        return None
        
    def head(self, url, headers=None, cookies=None, allow_redirects=True, timeout=None):
        """
        发送HEAD请求
        
        Args:
            url: 请求的URL
            headers: 请求头
            cookies: Cookies
            allow_redirects: 是否允许重定向
            timeout: 超时时间
            
        Returns:
            requests.Response: 响应对象
        """
        merged_headers = self._merge_headers(headers)
        merged_cookies = self._merge_cookies(cookies)
        timeout = timeout or self.timeout
        
        try:
            response = self.session.head(
                url=url,
                headers=merged_headers,
                cookies=merged_cookies,
                proxies=self._get_proxies(),
                allow_redirects=allow_redirects,
                timeout=timeout,
                verify=self.verify_ssl
            )
            return response
        except Exception as e:
            logger.error(f"发送HEAD请求时发生错误: {url} - {str(e)}")
            
        return None
        
    def request(self, method, url, **kwargs):
        """
        发送自定义请求
        
        Args:
            method: 请求方法
            url: 请求的URL
            **kwargs: 其他参数
            
        Returns:
            requests.Response: 响应对象
        """
        # 合并请求头和Cookies
        if 'headers' in kwargs:
            kwargs['headers'] = self._merge_headers(kwargs['headers'])
        else:
            kwargs['headers'] = self._merge_headers({})
            
        if 'cookies' in kwargs:
            kwargs['cookies'] = self._merge_cookies(kwargs['cookies'])
        else:
            kwargs['cookies'] = self._merge_cookies({})
            
        # 设置代理
        kwargs['proxies'] = self._get_proxies()
        
        # 设置默认参数
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', self.verify_ssl)
        
        try:
            response = self.session.request(method, url, **kwargs)
            return response
        except Exception as e:
            logger.error(f"发送{method}请求时发生错误: {url} - {str(e)}")
            
        return None
        
    def download_file(self, url, save_path, chunk_size=8192):
        """
        下载文件
        
        Args:
            url: 文件URL
            save_path: 保存路径
            chunk_size: 块大小
            
        Returns:
            bool: 下载是否成功
        """
        try:
            response = self.get(url, stream=True)
            if not response or response.status_code != 200:
                logger.error(f"下载文件失败, 状态码: {response.status_code if response else 'None'}")
                return False
                
            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        f.write(chunk)
                        
            return True
        except Exception as e:
            logger.error(f"下载文件时发生错误: {url} - {str(e)}")
            return False
            
    def submit_form(self, url, form_data, method='POST', headers=None, cookies=None):
        """
        提交表单
        
        Args:
            url: 表单提交URL
            form_data: 表单数据
            method: 提交方法
            headers: 请求头
            cookies: Cookies
            
        Returns:
            requests.Response: 响应对象
        """
        if method.upper() == 'POST':
            return self.post(url, data=form_data, headers=headers, cookies=cookies)
        else:
            return self.get(url, params=form_data, headers=headers, cookies=cookies)
            
    def _merge_headers(self, headers=None):
        """
        合并请求头
        
        Args:
            headers: 请求头
            
        Returns:
            dict: 合并后的请求头
        """
        merged = self.headers.copy()
        if headers:
            merged.update(headers)
        return merged
        
    def _merge_cookies(self, cookies=None):
        """
        合并Cookies
        
        Args:
            cookies: Cookies
            
        Returns:
            dict: 合并后的Cookies
        """
        merged = self.cookies.copy()
        if cookies:
            merged.update(cookies)
        return merged
        
    def _get_proxies(self):
        """
        获取代理配置
        
        Returns:
            dict: 代理配置
        """
        if not self.proxy:
            return {}
            
        return {
            'http': self.proxy,
            'https': self.proxy
        }
        
    def delay_request(self, min_delay=1, max_delay=3):
        """
        延迟请求以避免被目标网站检测为爬虫
        
        Args:
            min_delay: 最小延迟时间(秒)
            max_delay: 最大延迟时间(秒)
        """
        delay = random.uniform(min_delay, max_delay)
        time.sleep(delay) 