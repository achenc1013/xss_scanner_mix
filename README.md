# 深度XSS漏洞扫描器

这是一个全面的Web应用安全扫描工具，专注于检测XSS（跨站脚本）漏洞，同时也能够发现其他类型的Web安全漏洞。该工具支持多种扫描模式、不同级别的有效载荷和详细的漏洞报告。

## 功能特点

- **多种漏洞检测**：
  - XSS（反射型、存储型、DOM型）
  - CSRF（跨站请求伪造）
  - SQL注入
  - LFI（本地文件包含）
  - RFI（远程文件包含）
  - SSRF（服务器端请求伪造）
  - XXE（XML外部实体注入）

- **全面的扫描能力**：
  - 网站爬虫功能，自动发现可测试的URL
  - 表单和参数自动检测
  - 支持DOM分析
  - 支持不同测试级别（快速、标准、深度）
  - 支持多线程扫描

- **网页技术识别**：
  - 自动识别目标网站使用的编程语言（PHP、ASP.NET、Java、Python等）
  - 检测前端框架（React、Vue、Angular、jQuery等）
  - 识别Web服务器类型（Apache、Nginx、IIS等）
  - 识别CMS系统（WordPress、Joomla、Drupal等）
  - 框架版本指纹识别

- **高级WAF绕过功能**：
  - 自动检测目标是否启用Web应用防火墙(WAF)
  - 识别WAF类型（如Cloudflare、ModSecurity、AWS WAF等）
  - 自动调整有效载荷以绕过WAF检测
  - 多种绕过技术（编码变异、分段注入、定时执行等）
  - 自适应绕过策略，根据WAF反应调整攻击向量

- **增强的XSS检测**：
  - 支持三个级别(Level 1-3)的XSS有效载荷复杂度
  - 智能检测技术栈，自动选择最佳攻击向量
  - 多引擎检测策略（反射型、DOM型、存储型XSS）
  - 基于真实浏览器的XSS验证
  - 支持SVG、XML、JSON等特殊环境下的XSS检测
  - 包含最新的WAF绕过技术

- **高级功能**：
  - 有效载荷自动绕过WAF
  - 支持自定义有效载荷
  - 基于浏览器的漏洞验证
  - 支持漏洞利用
  - 支持代理和认证

- **详细报告**：
  - 多种报告格式（HTML、JSON、XML、TXT）
  - 详细的漏洞信息和修复建议
  - 风险评级
  - 网站技术栈分析报告

## 安装

### 要求
- Python 3.13+
- Chrome浏览器（如需浏览器测试）

### 安装步骤

1. 克隆仓库：
```bash
git clone https://github.com/achenc1013/XSS_Scanner.git
cd XSS_Scanner
```

2. 安装依赖：
```bash
pip install -r requirements.txt
```

3. 安装ChromeDriver（如需浏览器测试）：
```bash
# Windows使用以下命令：
pip install webdriver-manager

# Linux可能需要安装Chrome：
# sudo apt-get install google-chrome-stable
```

## 使用方法

### 基本用法

```bash
python xss_scanner.py -u https://example.com
```

### 更多示例

**扫描单个URL**：
```bash
python xss_scanner.py -u https://example.com
```

**扫描多个URL**：
```bash
python xss_scanner.py -f targets.txt
```

**深度扫描**：
```bash
python xss_scanner.py -u https://example.com --scan-level 3
```

**只扫描XSS漏洞**：
```bash
python xss_scanner.py -u https://example.com --scan-type xss
```

**使用浏览器进行DOM XSS检测**：
```bash
python xss_scanner.py -u https://example.com --browser
```

**利用发现的漏洞**：
```bash
python xss_scanner.py -u https://example.com --exploit
```

**生成HTML报告**：
```bash
python xss_scanner.py -u https://example.com -o report.html --format html
```

**使用代理**：
```bash
python xss_scanner.py -u https://example.com --proxy http://127.0.0.1:8080
```

### 命令行参数

```
必选参数:
  -u, --url URL              目标URL
  -f, --file FILE            包含目标URL的文件

可选参数:
  -d, --depth DEPTH          爬虫深度 (默认: 2)
  -t, --threads THREADS      线程数 (默认: 5)
  --timeout TIMEOUT          请求超时时间 (默认: 10秒)
  --user-agent USER_AGENT    自定义User-Agent
  --cookie COOKIE            请求Cookie
  --headers HEADERS          自定义HTTP头
  --proxy PROXY              HTTP代理
  --scan-level {1,2,3}       扫描级别: 1-快速, 2-标准, 3-深度 (默认: 2)
  --scan-type {all,xss,csrf,sqli,lfi,rfi,ssrf,xxe}
                             扫描类型 (默认: all)
  --payload-level {1,2,3}    Payload复杂度: 1-基础, 2-标准, 3-高级 (默认: 2)
  -o, --output OUTPUT        输出报告文件
  --format {txt,html,json,xml}
                             报告格式 (默认: html)
  -v, --verbose              显示详细输出
  --no-color                 禁用彩色输出

高级选项:
  --browser                  使用真实浏览器进行扫描
  --exploit                  尝试利用发现的漏洞
  --custom-payloads FILE     自定义Payload文件
  --exclude REGEX            排除URL模式 (正则表达式)
  --include REGEX            仅包含URL模式 (正则表达式)
  --auth USER:PASS           基本认证
```

## XSS漏洞案例

扫描器能够检测以下XSS攻击场景：

1. **网页留言板获取cookie**：检测表单提交中的XSS漏洞，可能导致cookie泄露
2. **CMS管理后台伪造钓鱼网站**：检测URL参数中的XSS漏洞，可能用于伪造管理界面
3. **图片处XSS攻击**：检测图片参数和属性中的XSS漏洞
4. **SVG-XSS**：检测SVG文件中的XML注入和XSS漏洞
5. **PDF-XSS**：检测PDF参数中的XSS漏洞
6. **浏览器翻译-XSS**：检测浏览器翻译功能中的XSS漏洞
7. **Flash-XSS**：检测Flash参数中的XSS漏洞
8. **XSS配合MSf钓鱼**：检测可能用于钓鱼的XSS漏洞
9. **XSS漏洞配合CSRF漏洞**：检测可能与CSRF组合的XSS漏洞
10. **XSS漏洞配合越权漏洞**：检测可能导致权限提升的XSS漏洞
11. **前端框架XSS**：检测React、Vue、Angular等前端框架中的XSS漏洞
12. **模板注入XSS**：检测模板引擎中的XSS漏洞，包括Jinja2、Twig、Handlebars等
13. **JSON-XSS**：检测JSON数据中的XSS漏洞，包括JSON.parse和eval使用不当
14. **WebSocket-XSS**：检测WebSocket通信中的XSS漏洞
15. **PostMessage-XSS**：检测跨域消息传递中的XSS漏洞

## XSS有效载荷级别

扫描器提供了三个级别的XSS有效载荷：

### Level 1 - 基础有效载荷
最基本的XSS向量，用于检测无防护的网站。包含15个常见的XSS攻击代码。

### Level 2 - 标准有效载荷
中等复杂度的XSS向量，包含绕过基本过滤的技术。包含约29个XSS攻击代码，结合了多种标签和事件处理程序。

### Level 3 - 高级有效载荷
最复杂的XSS向量，包含高级编码、混淆和WAF绕过技术。包含约50个复杂的XSS攻击代码，可以绕过大多数WAF和安全过滤器。

## XSS检测技术

扫描器使用多种技术来检测XSS漏洞：

1. **反射型XSS检测**：检测服务器响应中直接反射的用户输入
2. **DOM型XSS检测**：使用真实浏览器分析DOM操作和事件处理
3. **存储型XSS检测**：测试在一个页面提交的数据是否在另一个页面中触发XSS
4. **上下文感知检测**：根据XSS注入点的上下文选择合适的有效载荷
5. **WAF绕过技术**：使用多种编码和混淆技术绕过WAF防护

## 进阶用法

### 自定义有效载荷

创建一个文本文件，每行包含一个XSS有效载荷，然后使用`--custom-payloads`参数：

```bash
python xss_scanner.py -u https://example.com --custom-payloads my_payloads.txt
```

### 漏洞利用

使用`--exploit`参数启用漏洞利用功能：

```bash
python xss_scanner.py -u https://example.com --exploit
```

当发现漏洞时，扫描器将尝试进一步利用该漏洞，例如：
- XSS漏洞：尝试窃取cookie或会话信息
- SQL注入：尝试提取数据库信息
- 文件包含：尝试读取敏感文件

### 限制扫描范围

使用正则表达式包含或排除特定URL：

```bash
# 只扫描/admin/路径下的URL
python xss_scanner.py -u https://example.com --include "^https://example.com/admin/.*"

# 排除静态资源
python xss_scanner.py -u https://example.com --exclude "\.(jpg|css|js|png|gif)$"
```

## 安全和免责声明

此工具仅供安全研究和授权渗透测试使用。未经明确许可，对系统进行扫描可能违反法律。使用者需要：

1. 只在自己拥有的系统上或获得明确授权的系统上使用
2. 了解并遵守当地的网络安全法律和规定
3. 负责任地披露发现的安全漏洞

## 贡献

欢迎贡献代码、报告bug或提出功能建议。请通过以下方式参与：

1. Fork仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建Pull Request

## 许可证

本项目采用MIT许可证 - 详情请查看[LICENSE](LICENSE)文件。

## 联系方式

- 项目链接: [https://github.com/achenc1013/XSS_Scanner](https://github.com/achenc1013/XSS_Scanner)
- 联系邮箱: [1013199991@qq.com](mailto:1013199991@qq.com)

---

**注意**：此工具是为安全专业人员设计的，使用前请确保遵守所有适用的法律和法规。
