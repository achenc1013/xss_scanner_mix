#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
报告生成器模块，负责生成扫描结果报告
"""

import os
import json
import logging
import html
import datetime
from xml.dom.minidom import getDOMImplementation

logger = logging.getLogger('xss_scanner')

def format_details_for_txt(details):
    """
    格式化漏洞详情为文本格式
    
    Args:
        details: 漏洞详情，可能是字符串或字典
        
    Returns:
        str: 格式化后的漏洞详情文本
    """
    if isinstance(details, dict):
        return '\n  '.join([f"{k}: {v}" for k, v in details.items()])
    return str(details)

def format_details_for_html(details):
    """
    格式化漏洞详情为HTML格式
    
    Args:
        details: 漏洞详情，可能是字符串或字典
        
    Returns:
        str: 格式化后的HTML内容
    """
    if isinstance(details, dict):
        return '<br>'.join([f"<strong>{html.escape(str(k))}:</strong> {html.escape(str(v))}" for k, v in details.items()])
    return html.escape(str(details))

def generate_report(results, output_file, format_type='html'):
    """
    生成扫描报告
    
    Args:
        results: 扫描结果列表
        output_file: 输出文件路径
        format_type: 报告格式 (html, json, xml, txt)
    
    Returns:
        bool: 是否成功生成报告
    """
    # 创建输出目录（如果不存在）
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    try:
        if format_type == 'html':
            return generate_html_report(results, output_file)
        elif format_type == 'json':
            return generate_json_report(results, output_file)
        elif format_type == 'xml':
            return generate_xml_report(results, output_file)
        elif format_type == 'txt':
            return generate_txt_report(results, output_file)
        else:
            logger.error(f"不支持的报告格式: {format_type}")
            return False
    except Exception as e:
        logger.error(f"生成报告时发生错误: {str(e)}")
        return False

def generate_html_report(results, output_file):
    """
    生成HTML格式的报告
    
    Args:
        results: 扫描结果列表
        output_file: 输出文件路径
    
    Returns:
        bool: 是否成功生成报告
    """
    # 合并所有结果的统计信息
    total_stats = {
        'pages_scanned': 0,
        'forms_tested': 0,
        'parameters_tested': 0,
        'vulnerabilities_found': 0
    }
    
    all_vulnerabilities = []
    targets = []
    start_time = None
    total_time = 0
    
    for result in results:
        targets.append(result['target'])
        
        # 更新统计信息
        for key in total_stats:
            if key in result['statistics']:
                total_stats[key] += result['statistics'][key]
        
        # 收集所有漏洞
        all_vulnerabilities.extend(result['vulnerabilities'])
        
        # 计算总扫描时间
        if result.get('start_time') and result.get('end_time'):
            total_time += (result['end_time'] - result['start_time'])
        
        # 记录最早的开始时间
        if start_time is None or (result.get('start_time') and result['start_time'] < start_time):
            start_time = result.get('start_time')
    
    # 按漏洞类型分组
    vuln_by_type = {}
    for vuln in all_vulnerabilities:
        vuln_type = vuln['type']
        if vuln_type not in vuln_by_type:
            vuln_by_type[vuln_type] = []
        vuln_by_type[vuln_type].append(vuln)
    
    # 生成HTML报告
    html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS深度漏洞扫描报告</title>
    <style>
        body {{
            font-family: "Segoe UI", Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f9f9f9;
        }}
        .container {{
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            padding: 20px;
            margin-bottom: 30px;
        }}
        h1, h2, h3, h4 {{
            color: #2c3e50;
            margin-top: 20px;
        }}
        h1 {{
            text-align: center;
            color: #3498db;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 30px;
        }}
        .header-info {{
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
        }}
        .header-info div {{
            flex: 1;
            min-width: 250px;
            margin: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
            font-weight: bold;
        }}
        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        .severity-high {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .severity-medium {{
            color: #f39c12;
            font-weight: bold;
        }}
        .severity-low {{
            color: #3498db;
            font-weight: bold;
        }}
        .stats-container {{
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            margin-bottom: 20px;
        }}
        .stat-box {{
            flex: 1;
            min-width: 200px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 0 5px rgba(0, 0, 0, 0.1);
            padding: 15px;
            margin: 10px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 24px;
            font-weight: bold;
            color: #3498db;
            margin: 10px 0;
        }}
        .stat-label {{
            font-size: 14px;
            color: #7f8c8d;
        }}
        .vuln-details {{
            background-color: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 12px;
            margin: 10px 0;
            border-radius: 0 4px 4px 0;
        }}
        .no-vulns {{
            text-align: center;
            color: #27ae60;
            font-size: 18px;
            padding: 20px;
            background-color: #e8f8f5;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #7f8c8d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>XSS深度漏洞扫描报告</h1>
        
        <div class="header-info">
            <div>
                <h3>扫描信息</h3>
                <p><strong>目标网站：</strong> {', '.join(targets)}</p>
                <p><strong>扫描时间：</strong> {datetime.datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S') if start_time else 'N/A'}</p>
                <p><strong>总耗时：</strong> {total_time:.2f}秒</p>
            </div>
            <div>
                <h3>扫描范围</h3>
                <p><strong>扫描页面：</strong> {total_stats['pages_scanned']}</p>
                <p><strong>测试表单：</strong> {total_stats['forms_tested']}</p>
                <p><strong>测试参数：</strong> {total_stats['parameters_tested']}</p>
            </div>
        </div>
        
        <div class="stats-container">
            <div class="stat-box">
                <div class="stat-label">发现漏洞</div>
                <div class="stat-value">{total_stats['vulnerabilities_found']}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">页面扫描</div>
                <div class="stat-value">{total_stats['pages_scanned']}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">表单测试</div>
                <div class="stat-value">{total_stats['forms_tested']}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">参数测试</div>
                <div class="stat-value">{total_stats['parameters_tested']}</div>
            </div>
        </div>
    </div>

    <div class="container">
        <h2>漏洞详情</h2>
"""
    
    if all_vulnerabilities:
        for vuln_type, vulns in vuln_by_type.items():
            html_content += f"""
        <h3>{vuln_type} 漏洞 ({len(vulns)})</h3>
        <table>
            <tr>
                <th>#</th>
                <th>URL</th>
                <th>参数</th>
                <th>漏洞级别</th>
                <th>描述</th>
            </tr>
"""
            
            for i, vuln in enumerate(vulns, 1):
                severity_class = ""
                if vuln.get('severity') == '高':
                    severity_class = "severity-high"
                elif vuln.get('severity') == '中':
                    severity_class = "severity-medium"
                else:
                    severity_class = "severity-low"
                    
                html_content += f"""
            <tr>
                <td>{i}</td>
                <td>{html.escape(vuln.get('url', ''))}</td>
                <td>{html.escape(vuln.get('parameter', ''))}</td>
                <td class="{severity_class}">{html.escape(vuln.get('severity', ''))}</td>
                <td>{html.escape(vuln.get('description', ''))}</td>
            </tr>
            <tr>
                <td colspan="5">
                    <div class="vuln-details">
                        <p><strong>详情：</strong> {format_details_for_html(vuln.get('details', ''))}</p>
                        <p><strong>Payload：</strong> {html.escape(str(vuln.get('payload', '')))}</p>
                        <p><strong>修复建议：</strong> {html.escape(str(vuln.get('recommendation', '')))}</p>
                    </div>
                </td>
            </tr>
"""
            
            html_content += """
        </table>
"""
    else:
        html_content += """
        <div class="no-vulns">
            <p>恭喜！未发现任何漏洞。</p>
        </div>
"""
    
    html_content += """
    </div>
    
    <div class="footer">
        <p>扫描报告生成时间：""" + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
        <p>XSS深度漏洞扫描器 v1.0.0</p>
    </div>
</body>
</html>
"""
    
    # 写入文件
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return True

def generate_json_report(results, output_file):
    """
    生成JSON格式的报告
    
    Args:
        results: 扫描结果列表
        output_file: 输出文件路径
    
    Returns:
        bool: 是否成功生成报告
    """
    # 添加报告生成时间
    report = {
        'report_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'results': results
    }
    
    # 写入文件
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    return True

def generate_xml_report(results, output_file):
    """
    生成XML格式的报告
    
    Args:
        results: 扫描结果列表
        output_file: 输出文件路径
    
    Returns:
        bool: 是否成功生成报告
    """
    impl = getDOMImplementation()
    
    # 创建文档和根元素
    doc = impl.createDocument(None, "xss_scanner_report", None)
    root = doc.documentElement
    
    # 添加报告生成时间
    report_time = doc.createElement("report_time")
    report_time.appendChild(doc.createTextNode(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    root.appendChild(report_time)
    
    # 添加结果
    results_elem = doc.createElement("results")
    root.appendChild(results_elem)
    
    for result in results:
        result_elem = doc.createElement("result")
        results_elem.appendChild(result_elem)
        
        # 添加目标
        target_elem = doc.createElement("target")
        target_elem.appendChild(doc.createTextNode(result.get('target', '')))
        result_elem.appendChild(target_elem)
        
        # 添加扫描信息
        if 'scan_info' in result:
            scan_info_elem = doc.createElement("scan_info")
            result_elem.appendChild(scan_info_elem)
            
            for key, value in result['scan_info'].items():
                elem = doc.createElement(key)
                elem.appendChild(doc.createTextNode(str(value)))
                scan_info_elem.appendChild(elem)
        
        # 添加统计信息
        if 'statistics' in result:
            stats_elem = doc.createElement("statistics")
            result_elem.appendChild(stats_elem)
            
            for key, value in result['statistics'].items():
                elem = doc.createElement(key)
                elem.appendChild(doc.createTextNode(str(value)))
                stats_elem.appendChild(elem)
        
        # 添加漏洞
        if 'vulnerabilities' in result:
            vulns_elem = doc.createElement("vulnerabilities")
            result_elem.appendChild(vulns_elem)
            
            for vuln in result['vulnerabilities']:
                vuln_elem = doc.createElement("vulnerability")
                vulns_elem.appendChild(vuln_elem)
                
                for key, value in vuln.items():
                    elem = doc.createElement(key)
                    if isinstance(value, dict):
                        # 处理嵌套字典
                        for sub_key, sub_value in value.items():
                            sub_elem = doc.createElement(sub_key)
                            sub_elem.appendChild(doc.createTextNode(str(sub_value)))
                            elem.appendChild(sub_elem)
                    else:
                        elem.appendChild(doc.createTextNode(str(value)))
                    vuln_elem.appendChild(elem)
    
    # 写入文件
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(doc.toprettyxml(indent="  "))
    
    return True

def generate_txt_report(results, output_file):
    """
    生成TXT格式的报告
    
    Args:
        results: 扫描结果列表
        output_file: 输出文件路径
    
    Returns:
        bool: 是否成功生成报告
    """
    # 合并所有结果的统计信息
    total_stats = {
        'pages_scanned': 0,
        'forms_tested': 0,
        'parameters_tested': 0,
        'vulnerabilities_found': 0
    }
    
    all_vulnerabilities = []
    targets = []
    start_time = None
    total_time = 0
    
    for result in results:
        targets.append(result['target'])
        
        # 更新统计信息
        for key in total_stats:
            if key in result['statistics']:
                total_stats[key] += result['statistics'][key]
        
        # 收集所有漏洞
        all_vulnerabilities.extend(result['vulnerabilities'])
        
        # 计算总扫描时间
        if result.get('start_time') and result.get('end_time'):
            total_time += (result['end_time'] - result['start_time'])
        
        # 记录最早的开始时间
        if start_time is None or (result.get('start_time') and result['start_time'] < start_time):
            start_time = result.get('start_time')
    
    # 按漏洞类型分组
    vuln_by_type = {}
    for vuln in all_vulnerabilities:
        vuln_type = vuln['type']
        if vuln_type not in vuln_by_type:
            vuln_by_type[vuln_type] = []
        vuln_by_type[vuln_type].append(vuln)
    
    # 生成TXT报告
    txt_content = f"""
==========================================
       XSS深度漏洞扫描报告
==========================================

扫描信息
------------------------------------------
目标网站：{', '.join(targets)}
扫描时间：{datetime.datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S') if start_time else 'N/A'}
总耗时：{total_time:.2f}秒

扫描统计
------------------------------------------
发现漏洞：{total_stats['vulnerabilities_found']}
扫描页面：{total_stats['pages_scanned']}
测试表单：{total_stats['forms_tested']}
测试参数：{total_stats['parameters_tested']}

漏洞详情
==========================================
"""
    
    if all_vulnerabilities:
        for vuln_type, vulns in vuln_by_type.items():
            txt_content += f"""
{vuln_type} 漏洞 ({len(vulns)})
------------------------------------------
"""
            
            for i, vuln in enumerate(vulns, 1):
                txt_content += f"""
#{i}
URL: {vuln.get('url', '')}
参数: {vuln.get('parameter', '')}
漏洞级别: {vuln.get('severity', '')}
描述: {vuln.get('description', '')}
详情: {format_details_for_txt(vuln.get('details', ''))}
Payload: {vuln.get('payload', '')}
修复建议: {vuln.get('recommendation', '')}

"""
    else:
        txt_content += """
恭喜！未发现任何漏洞。

"""
    
    txt_content += f"""
==========================================
报告生成时间：{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
XSS深度漏洞扫描器 v1.0.0
==========================================
"""
    
    # 写入文件
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(txt_content)
    
    return True 