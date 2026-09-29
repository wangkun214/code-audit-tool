# -*- coding: utf-8 -*-
"""
规则库：定义静态源代码审计规则。

每条规则结构：
{
    "id":         规则唯一编号（语言前缀-类别-序号）
    "title":      规则名称
    "severity":   critical | high | medium | low | info
    "category":   见 CATEGORY_META
    "languages":  适用语言列表，["*"] 表示全部
    "pattern":    命中正则（单行匹配）
    "excludes":   同一行内命中则排除的正则列表（降噪）
    "path_exclude": 文件路径命中则跳过该规则（如测试代码）
    "guard":      上下文守护：{"window": n, "pattern": 正则}
                  在前 n 行内命中，说明已有防护 -> 自动降级为「已校验」
    "suppress_if": 文件级豁免正则（对整个文件内容匹配）。
                  命中则整条规则对该文件静默——用于「缺失型」检查
                  （如 Dockerfile 存在 USER 指令即豁免 CFG-DOCKER-001）。
    "description": 风险说明
    "remediation": 修复建议
    "cwe":        CWE 编号
    "confidence": high | medium | low（置信度）
    "references": 参考资料
}

规则优先级与冲突处理策略（引擎按此实现，修改规则时不得违背）：
1. 同文件同规则同行：仅保留首条（去重）。
2. 同文件不同规则命中同一行：按「severity 降序 -> confidence 降序 -> id 字典序」
   择优保留一条，其余自动丢弃并计入 conflict_dropped。
   典型场景：CFG-CI-001（CI 专用）与 SEC-KEY-004（通用凭据）命中同一配置行时，
   二者 severity/confidence 相同，按 id 序保留 CFG-CI-001——专用规则的语境更精确。
3. suppress_if（文件级豁免）优先级最高：命中即整条规则对该文件不生效，
   高于行级 pattern 与 guard。
4. guard（上下文防护）次之：上方 window 行内命中防护特征时该条自动豁免。
5. 新增规则时必须指明与其他规则的覆盖边界（引用本策略第 2 条说明让位关系），
   避免同一问题被两条规则以不同口径双报。
"""

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_META = {
    "critical": {"label": "严重", "color": "#b91c1c", "bg": "#fef2f2", "score": 9.5},
    "high":     {"label": "高危", "color": "#dc2626", "bg": "#fef2f2", "score": 7.5},
    "medium":   {"label": "中危", "color": "#d97706", "bg": "#fffbeb", "score": 5.0},
    "low":      {"label": "低危", "color": "#0284c7", "bg": "#f0f9ff", "score": 2.5},
    "info":     {"label": "提示", "color": "#64748b", "bg": "#f8fafc", "score": 0.5},
}

CATEGORY_META = {
    "injection":       "注入类",
    "secret":          "敏感信息泄露",
    "oob":             "越界与内存安全",
    "crypto":          "加密与随机数",
    "traversal":       "路径遍历与文件操作",
    "xss":             "跨站脚本",
    "deserialization": "反序列化",
    "ssrf":            "SSRF 与网络请求",
    "config":          "配置与部署风险",
    "quality":         "代码质量风险",
}

# 语言标识 -> 文件扩展名
LANG_EXT = {
    "go":         [".go"],
    "c":          [".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"],
    "python":     [".py"],
    "javascript": [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue"],
    "java":       [".java", ".kt", ".scala"],
    "php":        [".php"],
    "ruby":       [".rb"],
    "csharp":     [".cs"],
    "shell":      [".sh", ".bash", ".zsh"],
    "dockerfile": [".dockerfile"],
    "yaml":       [".yaml", ".yml"],
    "terraform":  [".tf"],
    "rego":       [".rego"],
    "sql":        [".sql"],
    "xml":        [".xml"],
    "html":       [".html", ".htm"],
}

EXT_LANG = {}
for _lang, _exts in LANG_EXT.items():
    for _e in _exts:
        EXT_LANG[_e] = _lang

# 无扩展名/特殊文件名 -> 语言
FILENAME_LANG = {
    "dockerfile": "dockerfile",
    "containerfile": "dockerfile",
}

# 默认跳过的目录
DEFAULT_EXCLUDES = [
    ".git", "node_modules", "vendor", "dist", "build",
    "testdata", ".idea", ".vscode", "__pycache__", ".venv", "venv", "target",
    "third_party", "thirdparty", "site-packages", ".terraform", "coverage",
    ".next", ".cache", "bower_components", "Pods",
]

# 默认跳过的文件后缀（二进制/压缩/媒体）
BINARY_EXT = [
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp", ".pdf",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".class",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".pyc", ".pyo",
    ".mp3", ".mp4", ".avi", ".mov", ".woff", ".woff2", ".ttf", ".eot", ".db", ".sqlite",
]


RULES = [
    # =====================================================================
    # 一、注入类
    # =====================================================================
    {
        "id": "INJ-SQL-001",
        "title": "SQL 语句通过字符串拼接构造",
        "severity": "high",
        "category": "injection",
        "languages": ["go"],
        "pattern": r"""(?i)(fmt\.Sprintf|[+])\s*\(?.*\b(SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|WHERE)\b""",
        "excludes": [r"(?i)\b(const|var)\s+\w*(query|sql|stmt)\w*\s*="],
        "description": "使用 fmt.Sprintf 或 + 号把变量拼进 SQL 语句，攻击者可通过构造输入改写查询语义，导致 SQL 注入、拖库或数据篡改。",
        "remediation": "改用参数化查询（database/sql 的 ? / $1 占位符）。示例：\n  stmt, _ := db.Prepare(\"SELECT * FROM users WHERE name = ?\")\n  rows, _ := stmt.Query(userInput)\n若必须动态表名/列名，请使用白名单校验，绝不拼接原始输入。",
        "cwe": "CWE-89",
        "confidence": "medium",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
    {
        "id": "INJ-SQL-002",
        "title": "SQL 语句动态拼接（多语言）",
        "severity": "high",
        "category": "injection",
        "languages": ["python", "javascript", "java", "php", "ruby", "csharp"],
        "pattern": r"""(?i)(query|sql|cursor\.execute|executeQuery|executeUpdate|db\.query|Db\.query|statement)\s*[=(]\s*[^)\n]*(\+|\$\{|%s|\.format\(|f["']|\bconcat\b)[^)\n]*["'][^)]*["']""",
        "description": "SQL 语句通过字符串拼接、格式化或模板字符串动态生成，用户输入可改变查询结构，形成注入。",
        "remediation": "使用参数化查询 / 预编译语句（PreparedStatement、cursor.execute(sql, params)、占位符绑定），禁止把用户输入拼进 SQL 文本。",
        "cwe": "CWE-89",
        "confidence": "medium",
        "references": ["https://owasp.org/Top10/A03_2021-Injection/"],
    },
    {
        "id": "INJ-CMD-001",
        "title": "命令执行参数由变量拼接",
        "severity": "high",
        "category": "injection",
        "languages": ["go"],
        "pattern": r"""exec\.(Command|CommandContext)\s*\(\s*(ctx\s*,\s*)?.{0,40}?"[^"]*[+%]""",
        "description": "exec.Command 的命令字符串中拼接了变量，若变量来自用户输入，攻击者可注入 shell 指令实现任意命令执行。",
        "remediation": "将命令与参数分开为独立参数传递，绝不拼接成单个字符串：\n  exec.Command(\"git\", \"clone\", userRepo)   // 正确\n  exec.Command(\"sh\", \"-c\", \"git clone \"+userRepo)  // 危险\n并对参数做白名单校验，禁用 sh -c 形式。",
        "cwe": "CWE-78",
        "confidence": "medium",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },
    {
        "id": "INJ-CMD-002",
        "title": "Shell 执行且参数含变量（多语言）",
        "severity": "high",
        "category": "injection",
        "languages": ["python", "javascript", "php", "ruby"],
        "pattern": r"""(?i)(os\.system|os\.popen|subprocess\.(call|run|Popen|check_output)|child_process\.(exec|execSync)|shell_exec|system\s*\(|`[^`]*\$\{?)\s*\(?[^)\n]*(\+|\$\{|%s|\.format\(|f["'])""",
        "excludes": [r"shell\s*=\s*False"],
        "description": "以字符串拼接方式调用系统命令（且默认启用 shell 解析），攻击者可注入分隔符执行任意指令。",
        "remediation": "使用数组参数形式并关闭 shell：\n  subprocess.run([\"ls\", \"-l\", path], shell=False, check=True)\n  child_process.execFile(\"ls\", [\"-l\", path])\n对输入做严格的字符白名单校验。",
        "cwe": "CWE-78",
        "confidence": "high",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },
    {
        "id": "INJ-LDAP-001",
        "title": "LDAP 查询拼接未转义输入",
        "severity": "medium",
        "category": "injection",
        "languages": ["go", "java", "python", "javascript"],
        "pattern": r"""(?i)(searchFilter|ldapFilter|filter)\s*[:=]\s*[^;\n]*["'][^"'\n]*(\+|\$\{|%s)[^;\n]*["']""",
        "description": "LDAP 查询过滤器由字符串拼接构造，可能导致 LDAP 注入，绕过认证或泄露目录数据。",
        "remediation": "对输入中的 * ( ) \\ NUL 等字符做转义（RFC 4515），或使用库提供的过滤器构造器 / 参数化 API。",
        "cwe": "CWE-90",
        "confidence": "low",
        "references": ["https://cwe.mitre.org/data/definitions/90.html"],
    },
    {
        "id": "INJ-LOG-001",
        "title": "日志格式化字符串含外部输入",
        "severity": "low",
        "category": "injection",
        "languages": ["go"],
        "pattern": r"""(?i)log\.(Printf|Fatalf|Panicf|Print)\s*\([^)]*\b(input|user|param|req|arg|body|query|name)\w*\b""",
        "description": "日志输出中直接使用外部输入作为格式串或内容，可能导致日志伪造、日志注入（CRLF）或格式化字符串攻击。",
        "remediation": "使用固定格式串占位符：log.Printf(\"user input: %s\", input)；对输入中的 \\r\\n 做过滤，避免日志伪造。",
        "cwe": "CWE-117",
        "confidence": "low",
        "references": ["https://cwe.mitre.org/data/definitions/117.html"],
    },

    {
        # 冲突边界：仅覆盖「动态执行代码字符串」（eval/exec/new Function），
        # 命令执行类（os.popen / subprocess 等）由 INJ-CMD-002 负责，SQL 注入由
        # INJ-SQL-001/002 负责，互不重叠。(?<![\w.$]) 排除 .exec()（JS 正则方法）、
        # ast.literal_eval 等成员调用形式的误报。
        "id": "INJ-EVAL-001",
        "title": "动态执行代码字符串（eval/exec）",
        "severity": "high",
        "category": "injection",
        "languages": ["python", "javascript", "php"],
        "pattern": r"""(?i)(?<![\w.$])(eval|exec)\s*\(|\bnew\s+Function\s*\(""",
        "excludes": [
            r"(?i)\b(eval|exec)\s*\(\s*\)\s*(//|$)",   # 空调用（如特性检测）
            r"(?i)(typeof\s+eval|window\.eval\s*=|delete\s+window\.eval)",
        ],
        "path_exclude": r"(?i)(_test\.go|\.test\.|\.spec\.|/tests?/|/testdata/|/fixtures?/|/mocks?/)",
        "description": "以字符串为代码源动态执行（Python eval/exec、JS eval/new Function、PHP eval）。只要字符串任何一部分来自外部输入，攻击者即可注入任意代码，通常直接等价于远程代码执行（RCE）。",
        "remediation": "1) 用结构化数据（JSON）替代代码字符串；\n2) Python 解析字面量一律用 ast.literal_eval；\n3) JS 用 JSON.parse / 查表映射替代 eval，避免间接 eval（setTimeout(\"...\")）；\n4) 确需执行时对输入做严格白名单校验，并在独立低权限沙箱中运行。",
        "cwe": "CWE-95",
        "confidence": "medium",
        "references": ["https://cwe.mitre.org/data/definitions/95.html"],
    },

    # =====================================================================
    # 二、敏感信息泄露
    # =====================================================================
    {
        "id": "SEC-KEY-001",
        "title": "疑似硬编码凭据（密码/密钥）",
        "severity": "high",
        "category": "secret",
        "languages": ["*"],
        "pattern": r"""(?i)\b\w*(password|passwd|pwd|secret|secretkey|secret_key|apikey|api_key|accesskey|access_key|private_key|privatekey|auth_token|credential)\w*\s*[:=]+\s*["'](?![a-z]{1,14}["'])[^"'\s]{5,}["']""",
        "excludes": [
            r"""(?i)["'](\*+|x{3,}|<[^>]*>|\$\{[^}]*\}|%[sdv]|placeholder|changeme|example|your[_-]?|test|dummy|sample|fake|none|null|empty|json|yaml|string|true|false|value|data|secret|password|token)["']""",
            r"(?i)(json|yaml|toml):?\"",
        ],
        "path_exclude": r"(?i)(_test\.go|\.test\.|\.spec\.|/tests?/|/testdata/|/fixtures?/|/mocks?/|/examples?/)",
        "description": "源码中直接写入了密码、密钥或令牌。代码一旦进入版本库或分发，凭据即视为泄露，可被用于横向渗透。",
        "remediation": "1) 立即轮换（吊销）该凭据；\n2) 改为从环境变量或密钥管理服务读取：os.Getenv(\"DB_PASSWORD\")；\n3) 引入 Vault / KMS / Secret Manager；\n4) 配置 .gitignore 并接入 gitleaks 等密钥扫描钩子。",
        "cwe": "CWE-798",
        "confidence": "medium",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    {
        # 覆盖 SEC-KEY-001 的盲区：配置文件 / .env / properties 中的「未加引号」明文凭据。
        # 命中条件（四重守卫，缺一不报）：
        #   1) 键名位于行首（含缩进），命中 password/secret/apikey 等敏感词；
        #   2) 值不以引号开头（排除已被 SEC-KEY-001 覆盖的字面量写法）；
        #   3) 值长度 ≥ 8；
        #   4) 值同时含大写、小写、数字（作为熵下界，挡住 human_readable 单词与纯十六进制哈希）。
        # 注意：大小写不敏感只作用于「键名」，用 (?i:...) 局部作用域开启；
        #       若在模式开头整体加 (?i)，会令 [A-Z] 守卫同时失效（这是必须避免的坑）。
        "id": "SEC-KEY-004",
        "title": "疑似硬编码凭据（未加引号的配置值）",
        "severity": "high",
        "category": "secret",
        "languages": ["*"],
        "pattern": (
            r"(?m)^[ \t]*(?:(?i:export|set)[ \t]+)?[A-Za-z0-9_.\-]*"
            r"(?i:password|passwd|secretkey|secret_key|secret|apikey|api_key|"
            r"accesskey|access_key|private_key|privatekey|auth_token|authtoken|"
            r"client_secret|clientsecret|db_pass|dbpass|jwt_secret|credential|pwd)"
            r"[A-Za-z0-9_.\-]*[ \t]*[:=][ \t]*"
            r"(?![\"'\s\[\{])"
            r"(?=[A-Za-z0-9_\-./+=@!#$%^&*~?]{8,})"
            r"(?=[^\s#;,'\"]*[A-Z])"
            r"(?=[^\s#;,'\"]*[a-z])"
            r"(?=[^\s#;,'\"]*[0-9])"
            r"[A-Za-z0-9_\-./+=@!#$%^&*~?]{8,}"
        ),
        "excludes": [
            r"^\s*#",                                                    # .env / properties 注释行
            r"(?i)(\$\{|\$\(|%[A-Za-z_]\w*%|\{\{[^}]*\}\})",             # 变量 / 模板 / 环境引用
            r"(?i)[:=][ \t]*[\w.$\-]+[ \t]*[\(\[.]",                      # 值以属性链或函数调用开始
            # 占位符：只在「值」部分查找关键词，避免误伤键名本身（如 password=...）
            r"(?i)[:=][ \t]*\S*(changeme|change_me|placeholder|your[_-]|example|dummy"
            r"|sample|fake|redacted|todo|fixme|unknown|undefined|notset|not_set)\S*",
            # 值的整体就是类型名 / 空值语义词
            r"(?i)[:=][ \t]*(string|boolean|integer|number|object|secret|password|token"
            r"|null|none|nil|true|false)[ \t]*$",
            r"(?:\*{3,}|x{6,}|\.{3,}|<[^>]{1,40}>)",                     # 掩码 / 尖括号占位
        ],
        "path_exclude": (
            r"(?i)(_test\.go|\.test\.|\.spec\.|/tests?/|/testdata/|/fixtures?/|/mocks?/|"
            r"/examples?/|/vendor/|/node_modules/|/dist/|/build/|go\.sum$|\.lock$|"
            r"package-lock\.json$|yarn\.lock$)"
        ),
        "description": "配置文件（.env / .properties / .yml / .ini）或代码中以「键 = 明文值」形式写入了未加引号的凭据，且值的长度与字符构成符合真实密钥特征。此类文件常被打包进镜像或随代码提交，等同于凭据公开发布。",
        "remediation": "1) 确认并立即轮换该凭据；\n2) 配置文件中改为引用环境变量：DB_PASSWORD=${DB_PASSWORD}（Spring 用 ${}，.env 保留键不赋值，由运行时注入）；\n3) 将 .env / *.properties 加入 .gitignore，仅提交 .env.example（值为空或占位符）；\n4) 接入密钥管理（Vault / KMS / Secret Manager）与 gitleaks 等提交前扫描。",
        "cwe": "CWE-798",
        "confidence": "medium",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    {
        "id": "SEC-KEY-002",
        "title": "硬编码云平台 AccessKey",
        "severity": "critical",
        "category": "secret",
        "languages": ["*"],
        "pattern": r"""(?i)(AKIA[0-9A-Z]{16}|(?<![A-Za-z0-9])LTAI[0-9A-Za-z]{12,}|(?<![A-Za-z0-9])AKID[0-9A-Za-z]{13,}|AIza[0-9A-Za-z_\-]{35})""",
        "path_exclude": r"""(?i)(go\.sum$|\.lock$|package-lock\.json$|yarn\.lock$|/vendor/)""",
        "description": "检测到云平台（AWS / 阿里云 / 腾讯云 / GCP）的 AccessKey 标识。此类凭据泄露可直接导致云资源被接管、产生高额费用或数据外泄。",
        "remediation": "立即在云控制台禁用/轮换该 AK，改用实例角色（RAM Role / IAM Role）或临时 STS 凭证；开启云审计与费用告警。",
        "cwe": "CWE-798",
        "confidence": "high",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    {
        "id": "SEC-KEY-003",
        "title": "硬编码 API Token / 私钥标识",
        "severity": "critical",
        "category": "secret",
        "languages": ["*"],
        "pattern": r"""(ghp_[0-9A-Za-z]{36}|gho_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,}|sk-[A-Za-z0-9]{20,}|xox[baprs]-[0-9A-Za-z\-]{10,}|-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP|PRIVATE)\s+PRIVATE\s+KEY-----|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})""",
        "path_exclude": r"""(?i)(go\.sum$|\.lock$|package-lock\.json$|yarn\.lock$|/vendor/)""",
        "description": "检测到 GitHub Token、OpenAI/Stripe 风格密钥、Slack Token、SSH/TLS 私钥或 JWT 明文。私钥泄露等同于身份被完全冒用。",
        "remediation": "1) 立即吊销并重新签发；\n2) 私钥文件移出仓库并加入 .gitignore；\n3) 使用密钥托管（Vault / KMS / GitHub Secrets）；\n4) 清理 Git 历史（git filter-repo / BFG）。",
        "cwe": "CWE-798",
        "confidence": "high",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    {
        "id": "SEC-LOG-001",
        "title": "日志中可能输出敏感字段",
        "severity": "medium",
        "category": "secret",
        "languages": ["*"],
        "pattern": r"""(?i)(log\.\w+|logger?\.(info|debug|warn|error)|console\.log|print(f|ln)?)\s*\([^)\n]*\b(password|passwd|pwd|secret|token|apikey|api_key|authorization|cookie|creditcard|idcard|ssn)\b""",
        "description": "日志语句中直接输出了密码、令牌或证件号等敏感字段，日志文件往往权限宽松，易造成敏感信息二次泄露。",
        "remediation": "输出前脱敏：仅打印字段长度或掩码（如 token[:4] + \"****\"）；建立统一日志脱敏工具函数并强制使用。",
        "cwe": "CWE-532",
        "confidence": "medium",
        "references": ["https://cwe.mitre.org/data/definitions/532.html"],
    },
    {
        "id": "SEC-URL-001",
        "title": "URL 中内嵌明文凭据",
        "severity": "high",
        "category": "secret",
        "languages": ["*"],
        "pattern": r"""["'][a-zA-Z][a-zA-Z0-9+.\-]{2,}://[^/"'\s:]+:[^/"'\s@]+@[^"'\s]+["']""",
        "excludes": [r"""(?i)["'][a-z]+://(user|username|user|admin|xxx|\$\{)[:：]"""],
        "description": "连接串中出现 scheme://user:password@host 形式，凭据以明文形式存在于代码与日志中。",
        "remediation": "改用环境变量或配置中心注入凭据，并使用 DSN 参数分离：\n  dsn := fmt.Sprintf(\"%s:%s@tcp(%s)/%s\", os.Getenv(\"DB_USER\"), os.Getenv(\"DB_PASS\"), host, db)",
        "cwe": "CWE-798",
        "confidence": "medium",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    {
        "id": "SEC-DEBUG-001",
        "title": "调试开关/详细错误对外暴露",
        "severity": "low",
        "category": "secret",
        "languages": ["*"],
        "pattern": r"""(?i)\b(debug|verbose|trace)\b\s*[:=]\s*(true|True|1)\b""",
        "excludes": [r"(?i)(debug\s*(log|level|f|ger)\w*\s*[:=])", r"(?i)flags?\.(Bool|String)"],
        "path_exclude": r"(?i)(_test\.go|\.test\.|\.spec\.)",
        "description": "调试模式在代码中硬编码为开启，可能向攻击者暴露堆栈、SQL 语句、内部路径等敏感调试信息。",
        "remediation": "生产环境必须关闭调试开关，通过环境变量或构建标签控制：debug := os.Getenv(\"APP_ENV\") != \"production\"。",
        "cwe": "CWE-489",
        "confidence": "low",
        "references": ["https://cwe.mitre.org/data/definitions/489.html"],
    },

    # =====================================================================
    # 三、越界与内存安全
    # =====================================================================
    {
        "id": "OOB-INDEX-001",
        "title": "索引表达式含算术运算且未见长度校验",
        "severity": "medium",
        "category": "oob",
        "languages": ["go", "java", "javascript", "csharp", "c"],
        "pattern": r"""\[\s*:?\s*[a-zA-Z_]\w{0,8}\s*[+\-]\s*(\d{1,4}|[a-zA-Z_]\w{0,8})\s*\]""",
        "excludes": [
            r"^\s*(//|/\*|\*)",
            r"(?i)(len|cap|length)\s*\(",
            r"\[\s*\]",
        ],
        "guard": {"window": 8, "pattern": r"(?i)(len\s*\(|cap\s*\(|\.length|>\s*len\s*\(|>=?\s*len\s*\(|bounds|clamp|min\s*\()"},
        "path_exclude": r"(?i)(_test\.go)",
        "description": "使用「变量 ± 偏移」的形式计算数组/切片索引（如 buf[i-1]、parts[n+1]），但上方未见长度或边界校验。当偏移越过 [0, len) 范围时，Go/Java 会 panic 或抛异常，C/C++ 则可能造成真实的越界读写，导致拒绝服务或内存破坏。",
        "remediation": "取值前校验索引范围：\n  if i <= 0 || i+1 >= len(buf) {\n      return fmt.Errorf(\"index out of range: %d\", i)\n  }\n  v := buf[i-1]\n注意 i 的类型：无符号整数做减法会回绕为极大值，务必先判 i 是否大于偏移量。",
        "cwe": "CWE-125",
        "confidence": "low",
        "references": ["https://cwe.mitre.org/data/definitions/125.html"],
    },
    {
        "id": "OOB-SLICE-001",
        "title": "切片截取边界含算术运算且未见长度约束",
        "severity": "medium",
        "category": "oob",
        "languages": ["go", "java", "javascript", "csharp", "c"],
        "pattern": r"""\[\s*[^\]\n:]{0,20}:\s*[a-zA-Z_]\w{0,8}\s*[+\-]\s*(\d{1,4}|[a-zA-Z_]\w{0,8})\s*\]""",
        "excludes": [
            r"^\s*(//|/\*)",
            r"(?i)(len|cap|\.length)\s*\(",
            r"^\s*\w+\s*:?=",
        ],
        "guard": {"window": 8, "pattern": r"(?i)(len\s*\(|cap\s*\(|if\s+.*len\s*\(|min\s*\(|clamp)"},
        "path_exclude": r"(?i)(_test\.go)",
        "description": "切片截取/索引表达式中包含加减运算（如 s[offset:offset+n]、b[pos-1:]），上界未做收敛。越界会 panic（DoS），C 系语言则可能读写越界内存。",
        "remediation": "截取前收敛边界：\n  end := min(len(s), offset+n)\n  if offset < 0 || offset > len(s) { return err }\n  v := s[offset:end]",
        "cwe": "CWE-125",
        "confidence": "low",
        "references": ["https://cwe.mitre.org/data/definitions/125.html"],
    },
    {
        "id": "OOB-UNSAFE-001",
        "title": "使用 unsafe 包进行指针运算",
        "severity": "high",
        "category": "oob",
        "languages": ["go"],
        "pattern": r"""\bunsafe\.(Pointer|Sizeof|Offsetof|Alignof|Slice|SliceData|String|StringData|Add)\b""",
        "description": "unsafe 包绕过 Go 的内存安全保证，指针运算/类型双关一旦边界计算错误即造成任意内存读写、崩溃或信息泄露。",
        "remediation": "优先使用标准库安全 API 替代；确需使用时必须：\n1) 严格校验长度与偏移；\n2) 用 runtime.KeepAlive 防止对象被提前回收；\n3) 编写专项单测与 fuzz 测试覆盖边界；\n4) 增加代码评审强制卡点。",
        "cwe": "CWE-823",
        "confidence": "high",
        "references": ["https://cwe.mitre.org/data/definitions/823.html"],
    },
    {
        "id": "OOB-CGO-001",
        "title": "使用 cgo 调用原生代码",
        "severity": "medium",
        "category": "oob",
        "languages": ["go"],
        "pattern": r"""(?m)^\s*(//\s*#cgo|/\*\s*#cgo|import\s+"C")""",
        "description": "cgo 引入 C 代码，C 侧缓冲区读写不受 Go 内存安全检查约束，是越界/内存破坏漏洞的高发区。",
        "remediation": "尽量以纯 Go 实现替代；必须使用 cgo 时，对所有 C 侧缓冲区拷贝执行长度上限校验，启用 -fsanitize=address 做检测，并对 C 结构体做严格 ABI 校验。",
        "cwe": "CWE-787",
        "confidence": "high",
        "references": ["https://cwe.mitre.org/data/definitions/787.html"],
    },
    {
        "id": "OOB-BUFFER-001",
        "title": "固定缓冲区拷贝未见长度截断",
        "severity": "high",
        "category": "oob",
        "languages": ["c", "java", "csharp"],
        "pattern": r"""(?i)\b(memcpy|memmove|strcpy|strcat|strncpy|strncat|sprintf|vsprintf|wcscpy|arraycopy|BlockCopy)\s*\([^)\n]{0,80}\)""",
        "excludes": [r"(?i)(len\s*\(|\.length|sizeof|min\s*\(|snprintf)"],
        "guard": {"window": 6, "pattern": r"(?i)(len\s*\(|\.length|sizeof|min\s*\(|>\s*len)"},
        "description": "向固定长度缓冲区执行拷贝/拼接，未见到长度截断逻辑。源数据超长时将造成缓冲区溢出或相邻数据被覆盖（CWE-787），是内存破坏漏洞的典型成因。",
        "remediation": "拷贝前做长度上限收敛：\n  memcpy(dst, src, min(len(src), sizeof(dst)));\n  禁止使用 strcpy / strcat / sprintf，改用 snprintf / strncpy_s / 语言自带的安全 API。",
        "cwe": "CWE-787",
        "confidence": "medium",
        "references": ["https://cwe.mitre.org/data/definitions/787.html"],
    },

    # =====================================================================
    # 四、加密与随机数
    # =====================================================================
    {
        "id": "CRY-WEAK-001",
        "title": "使用已被攻破的弱哈希算法",
        "severity": "medium",
        "category": "crypto",
        "languages": ["go", "python", "javascript", "java", "php", "ruby", "csharp"],
        "pattern": r"""(?i)\b(MD5|MessageDigest\.getInstance\s*\(\s*["']MD5|sha1|SHA-1|crypto\.createHash\s*\(\s*["'](md5|sha1)|hashlib\.(md5|sha1)|DigestUtils\.md5)\b""",
        "description": "MD5/SHA-1 已被证明存在碰撞攻击，用于口令存储、签名校验或完整性保护时会导致伪造与绕过。",
        "remediation": "口令存储改用 Argon2id / bcrypt / scrypt（带盐且迭代次数足够）；\n完整性校验改用 SHA-256 / SHA-3 或 HMAC-SHA256。",
        "cwe": "CWE-327",
        "confidence": "high",
        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
    },
    {
        "id": "CRY-WEAK-002",
        "title": "使用弱加密算法或分组模式",
        "severity": "high",
        "category": "crypto",
        "languages": ["go", "python", "javascript", "java", "php", "ruby", "csharp"],
        "pattern": r"""(?i)\b(DES|3DES|TripleDES|RC2|RC4|ARC4|Blowfish|ECB|MODE_ECB|Cipher\.getInstance\s*\(\s*["'](DES|RC4|.*ECB|.*NoPadding))\b""",
        "description": "DES/3DES/RC4 密钥空间不足或算法存在已知缺陷；ECB 模式不隐藏明文结构（相同明文块产生相同密文块），均不安全。",
        "remediation": "对称加密统一使用 AES-256-GCM 或 ChaCha20-Poly1305；\n必须使用分组模式时选择 GCM/CBC+HMAC，严禁 ECB；\n随机 IV 每次加密唯一生成并随密文存储。",
        "cwe": "CWE-327",
        "confidence": "high",
        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
    },
    {
        "id": "CRY-RAND-001",
        "title": "使用非密码学安全随机数",
        "severity": "medium",
        "category": "crypto",
        "languages": ["go", "python", "javascript", "java", "ruby"],
        "pattern": r"""(?i)(math/rand|rand\.Intn|rand\.Int63|rand\.Float64|\brandom\.(randint|random|choice|sample)\b|Math\.random\(\)|java\.util\.Random|new\s+Random\s*\()""",
        "description": "math/rand（或等价非密码学随机源）可被预测，用于生成令牌、会话 ID、加密密钥或验证码时可被枚举/碰撞。",
        "remediation": "Go 使用 crypto/rand：\n  b := make([]byte, 32); rand.Read(b)\nPython 使用 secrets 模块；Java 使用 SecureRandom；不要对时间种子做哈希当作随机源。",
        "cwe": "CWE-338",
        "confidence": "medium",
        "references": ["https://cwe.mitre.org/data/definitions/338.html"],
    },
    {
        "id": "CRY-TLS-001",
        "title": "TLS 证书校验被显式关闭",
        "severity": "high",
        "category": "crypto",
        "languages": ["go", "python", "javascript", "java", "csharp"],
        "pattern": r"""(?i)(InsecureSkipVerify\s*:\s*true|verify\s*=\s*False|rejectUnauthorized\s*:\s*false|setVerify\s*\(\s*false|TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|checkServerIdentity\s*:\s*\(\s*\)\s*=>)""",
        "description": "关闭 TLS 证书校验使连接不再验证对端身份，中间人可静默解密或篡改通信内容。",
        "remediation": "恢复证书链与主机名校验；内网自签场景应把 CA 证书加入受信任根（x509.CertPool）而非直接跳过校验；\n如需调试开关，必须限定在测试构建标签内。",
        "cwe": "CWE-295",
        "confidence": "high",
        "references": ["https://cwe.mitre.org/data/definitions/295.html"],
    },
    {
        "id": "CRY-HARDCODE-001",
        "title": "加密密钥/IV 硬编码在代码中",
        "severity": "high",
        "category": "crypto",
        "languages": ["go", "python", "javascript", "java", "php", "csharp"],
        "pattern": r"""(?i)\b(encryptionKey|secretKey|aesKey|privateKey|\biv\b|salt|nonce)\b\s*[:=]+\s*(\[\]byte\s*\(|\[\]byte\{|")[^;\n]{6,}""",
        "excludes": [r"(?i)(nil|null|make\(|os\.Getenv|config\.|viper\.|env\.)"],
        "description": "对称密钥、IV 或盐值硬编码在源码中，任何拿到代码的人都能解密全部历史密文，等于加密失效。",
        "remediation": "密钥从 KMS / Vault / 环境变量读取并定期轮换；\nIV/Nonce 必须每次加密随机生成（无需保密但绝不能复用）；\n盐值使用 crypto/rand 生成并随密文存储。",
        "cwe": "CWE-321",
        "confidence": "medium",
        "references": ["https://cwe.mitre.org/data/definitions/321.html"],
    },

    # =====================================================================
    # 五、路径遍历与文件操作
    # =====================================================================
    {
        "id": "TRAV-PATH-001",
        "title": "文件路径由外部输入拼接",
        "severity": "high",
        "category": "traversal",
        "languages": ["go", "python", "javascript", "java", "php", "csharp"],
        "pattern": r"""(?i)(filepath\.Join|path\.Join|os\.path\.join|path\.join|Paths\.get|Files\.(newInputStream|readAllBytes|copy)|os\.Open|ioutil\.ReadFile|os\.ReadFile|readFile|fopen)\s*\([^)\n]{0,80}\b(req|request|input|user|param|query|fileName|filename|userPath|userpath)\w*\b""",
        "excludes": [r"""(?i)(filepath\.Join\s*\(\s*[a-zA-Z_]\w*\s*,\s*["'])"""],
        "guard": {"window": 10, "pattern": r"(?i)(filepath\.Clean|filepath\.Abs|filepath\.Rel|HasPrefix|SecureJoin|isSubPath|ensure.*within)"},
        "description": "用户可控参数直接参与文件路径构造，攻击者可用 ../ 跳出受限目录读取任意文件（路径遍历 / 任意文件读取）。",
        "remediation": "1) 使用白名单映射：仅允许预定义的文件 ID；\n2) 拼接后规范化并校验前缀：\n  clean := filepath.Clean(filepath.Join(base, userPath))\n  if !strings.HasPrefix(clean, base+string(os.PathSeparator)) { return err }\n3) 使用 os.Root（Go 1.24+）或 openat2 限制访问根目录。",
        "cwe": "CWE-22",
        "confidence": "medium",
        "references": ["https://cwe.mitre.org/data/definitions/22.html"],
    },
    {
        "id": "TRAV-ZIP-001",
        "title": "压缩包解压未校验条目路径（Zip Slip）",
        "severity": "high",
        "category": "traversal",
        "languages": ["go", "python", "javascript", "java"],
        "pattern": r"""(?i)(filepath\.Join|path\.Join|os\.path\.join|path\.join|Paths\.get|\.join|os\.Create|os\.WriteFile|ioutil\.WriteFile|Files\.(newOutputStream|write|copy))\s*\([^)\n]{0,70}\b\w{1,24}\.(Name|FileName|Filename|name)\b""",
        "guard": {"window": 6, "pattern": r"(?i)(HasPrefix|isSubPath|filepath\.Rel|absPath|SecureJoin|ensure.*(within|inside)|cleaned)"},
        "description": "在解压/落盘时使用压缩包条目的原始文件名（entry.Name）拼接目标路径。若条目名包含 ../ 或绝对路径，可写入目标目录之外的任意位置覆盖系统文件（Zip Slip），常被升级为远程代码执行。",
        "remediation": "解压每个条目时校验规范化路径仍位于目标目录内：\n  target := filepath.Join(dest, hdr.Name)\n  if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) {\n      return fmt.Errorf(\"illegal path: %s\", hdr.Name)\n  }\n同时限制解压总大小与条目数量（防 Zip Bomb）。",
        "cwe": "CWE-22",
        "confidence": "medium",
        "references": ["https://snyk.io/research/zip-slip-vulnerability"],
    },
    {
        "id": "TRAV-PERM-001",
        "title": "创建文件权限过于宽松",
        "severity": "medium",
        "category": "traversal",
        "languages": ["go", "shell", "python"],
        "pattern": r"""(?i)(os\.(Create|OpenFile|WriteFile|Mkdir|MkdirAll|Chmod)|OpenFile|chmod|Chmod|umask)\s*\([^)\n]{0,60}(0?777|0?666|0?776)\b""",
        "description": "文件/目录权限设置为 world-writable 或 world-readable（0777/0666 等）。同机其他用户可篡改配置或读取敏感文件。注意：0755 是可执行文件/目录的常规权限，本条不对其进行告警，避免与最小权限建议自相矛盾。",
        "remediation": "遵循最小权限：\n  配置文件 0600，可执行文件 0755，目录 0750；\n  os.WriteFile(path, data, 0600)  // 不要用 0666\n  使用 umask 022 兜底。",
        "cwe": "CWE-732",
        "confidence": "medium",
        "references": ["https://cwe.mitre.org/data/definitions/732.html"],
    },
    {
        "id": "TRAV-TEMP-001",
        "title": "使用可预测的临时文件路径",
        "severity": "medium",
        "category": "traversal",
        "languages": ["go", "python", "c"],
        "pattern": r"""(?i)(/tmp/|os\.TempDir\s*\(\s*\)\s*\+|C:\\\\Windows\\\\Temp|tempfile\.mktemp|/var/tmp/)""",
        "description": "使用固定或可预测的临时文件路径，可被本地攻击者利用符号链接抢占（TOCTOU），实现任意文件覆盖或提权。",
        "remediation": "使用安全的临时文件 API：\n  f, err := os.CreateTemp(\"\", \"prefix-*.tmp\")   // Go\n  tempfile.NamedTemporaryFile()                 // Python\n创建后立即设为 0600，用完及时删除。",
        "cwe": "CWE-377",
        "confidence": "medium",
        "references": ["https://cwe.mitre.org/data/definitions/377.html"],
    },

    # =====================================================================
    # 六、跨站脚本 XSS
    # =====================================================================
    {
        "id": "XSS-OUT-001",
        "title": "未转义输出到 HTML（潜在 XSS）",
        "severity": "high",
        "category": "xss",
        "languages": ["go", "python", "javascript", "php", "java"],
        "pattern": r"""(?i)(Fprintf?\s*\(\s*\w*(w|Writer|resp|response)|write\s*\(|innerHTML\s*=|document\.write\s*\(|echo\s+|print\s*\(|Response\.Write\s*\()\s*[^;\n]{0,60}(<[a-zA-Z/!])""",
        "excludes": [r"(?i)(html/template|template\.HTMLEscapeString|escapeHtml|htmlspecialchars|bluemonday|DOMPurify|sanitize)"],
        "description": "把数据直接写入 HTML 输出流而未做转义，若数据来自用户输入（反射型/存储型）即可注入脚本，导致会话劫持、钓鱼与数据窃取。",
        "remediation": "1) Go 使用 html/template（自动上下文转义），不要用 text/template 输出 HTML；\n2) 前端避免 innerHTML，改用 textContent 或经 DOMPurify 净化；\n3) 配置 CSP 头：Content-Security-Policy: default-src 'self'。",
        "cwe": "CWE-79",
        "confidence": "low",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },
    {
        "id": "XSS-TEMPLATE-001",
        "title": "text/template 用于 HTML 渲染",
        "severity": "medium",
        "category": "xss",
        "languages": ["go"],
        "pattern": r""""text/template"|texttemplate\.New""",
        "description": "text/template 不做 HTML 上下文转义，用于网页渲染时用户数据中的 <script> 会被原样输出，形成 XSS。",
        "remediation": "渲染 HTML 一律使用 html/template：\n  import \"html/template\"\n  t, _ := template.New(\"page\").Parse(tpl)",
        "cwe": "CWE-79",
        "confidence": "medium",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },
    {
        "id": "XSS-TEMPLATE-002",
        "title": "模板内容使用不安全类型绕过转义",
        "severity": "medium",
        "category": "xss",
        "languages": ["go"],
        "pattern": r"""\btemplate\.(HTML|JS|URL|CSS|HTMLAttr|JSStr|Srcset)\s*\(""",
        "description": "template.HTML / template.JS 等类型会告知模板引擎「内容已安全」，跳过自动转义。若包裹的是用户输入，等价于主动引入 XSS。",
        "remediation": "只有在内容确实经过可信白名单净化后才使用这些类型；\n优先改用普通 string 让模板自动转义；\n对富文本使用 bluemonday 白名单净化后再包 template.HTML。",
        "cwe": "CWE-79",
        "confidence": "medium",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },

    # =====================================================================
    # 七、反序列化
    # =====================================================================
    {
        "id": "DESER-PICKLE-001",
        "title": "反序列化不可信数据（高危）",
        "severity": "high",
        "category": "deserialization",
        "languages": ["python", "ruby", "php", "java", "go", "javascript"],
        "pattern": r"""(?i)(pickle\.loads?|cPickle\.loads?|yaml\.load\s*\(|marshal\.loads|Marshal\.load|\.readObject\s*\(|ObjectInputStream|XMLDecoder|BinaryFormatter|unserialize\s*\(|node-serialize|jsonpickle\.decode)""",
        "excludes": [r"(?i)(yaml\.safe_load|yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.SafeLoader|SafeLoader)"],
        "description": "对不可信输入执行反序列化时，攻击者可构造恶意对象触发任意代码执行、命令执行或拒绝服务（如 Java ysoserial、Python pickle RCE）。",
        "remediation": "1) 优先改用 JSON 等纯数据格式；\n2) Python 用 yaml.safe_load / json.loads；\n3) Java 使用白名单过滤 ObjectInputFilter，或改用 Protobuf/JSON；\n4) 反序列化前做完整性签名校验（HMAC）。",
        "cwe": "CWE-502",
        "confidence": "high",
        "references": ["https://cwe.mitre.org/data/definitions/502.html"],
    },
    {
        "id": "DESER-GOB-001",
        "title": "gob 反序列化外部数据",
        "severity": "medium",
        "category": "deserialization",
        "languages": ["go"],
        "pattern": r"""gob\.NewDecoder|gob\.Decode""",
        "description": "gob 可反序列化任意注册类型，处理不可信网络数据时存在类型混淆与内存放大（DoS）风险。",
        "remediation": "对外部数据改用 JSON/Protobuf 并做严格结构校验；\n必须使用 gob 时限制输入大小、仅注册必要类型，并在可信边界内使用。",
        "cwe": "CWE-502",
        "confidence": "medium",
        "references": ["https://cwe.mitre.org/data/definitions/502.html"],
    },

    # =====================================================================
    # 八、SSRF 与网络请求
    # =====================================================================
    {
        "id": "SSRF-REQ-001",
        "title": "HTTP 请求 URL 来自外部输入（潜在 SSRF）",
        "severity": "medium",
        "category": "ssrf",
        "languages": ["go", "python", "javascript", "java", "php"],
        "pattern": r"""(?i)(http\.(Get|Post|Head|NewRequest|NewRequestWithContext)|requests\.(get|post|put|head)|axios\.(get|post)|fetch\s*\(|urlopen|HttpClient|WebClient)\s*\(\s*(ctx\s*,\s*)?[^)\n]{0,40}\b(input|url|uri|target|host|endpoint|req|param|user|addr|link|redirect)\w*\b""",
        "excludes": [r"""(?i)["']https?://[a-z0-9.\-]+"""],
        "description": "请求目标地址由用户可控参数决定，攻击者可让服务端访问内网地址/云元数据（169.254.169.254），形成 SSRF，进而探测内网或窃取实例凭证。",
        "remediation": "1) 目标地址使用白名单（域名+端口）；\n2) 解析后校验 IP 不属于私网/环回/链路本地段（10./172.16-31./192.168./127./169.254.）；\n3) 禁用重定向或逐跳校验；\n4) 云环境强制使用 IMDSv2 并限制出口。",
        "cwe": "CWE-918",
        "confidence": "low",
        "references": ["https://cwe.mitre.org/data/definitions/918.html"],
    },
    {
        "id": "SSRF-REDIR-001",
        "title": "HTTP 重定向目标未做限制",
        "severity": "medium",
        "category": "ssrf",
        "languages": ["go", "python", "javascript", "java", "php"],
        "pattern": r"""(?i)(http\.Redirect\s*\(|Redirect\s*\(|res\.redirect\s*\(|response\.sendRedirect\s*\(|header\s*\(\s*["']Location|setHeader\s*\(\s*["']Location)[^;\n]{0,60}\b(input|url|uri|target|next|redirect|return|param|req|user)\w*\b""",
        "description": "跳转地址直接取自请求参数，可被用于开放式重定向，配合钓鱼、OAuth 凭证窃取或 SSRF 绕过。",
        "remediation": "跳转目标使用相对路径或白名单域名校验：\n  if u, err := url.Parse(target); err != nil || u.Host != \"\" && !allowed(u.Host) { return err }\n",
        "cwe": "CWE-601",
        "confidence": "medium",
        "references": ["https://cwe.mitre.org/data/definitions/601.html"],
    },

    # =====================================================================
    # 九、配置与部署风险
    # =====================================================================
    {
        "id": "CFG-CORS-001",
        "title": "CORS 允许任意来源",
        "severity": "medium",
        "category": "config",
        "languages": ["*"],
        "pattern": r"""(?i)(Access-Control-Allow-Origin\s*[:=]\s*["']?\*|AllowOrigins?\s*[:=]\s*[^\n]*["']\*["']|cors\s*\(\s*\{\s*origin\s*:\s*["']\*["']|allow_origins\s*=\s*\[\s*["']\*["'])""",
        "description": "跨域策略放开为 *，若同时允许携带凭据（Allow-Credentials: true），任意站点可读取用户私有数据，造成越权与信息泄露。",
        "remediation": "显式列出可信来源白名单：\n  Access-Control-Allow-Origin: https://app.example.com\n禁止 Origin: * 与 Allow-Credentials: true 同时出现；对 Origin 做服务端校验后再回写。",
        "cwe": "CWE-942",
        "confidence": "high",
        "references": ["https://cwe.mitre.org/data/definitions/942.html"],
    },
    {
        # 冲突边界：本条只负责「整个 Dockerfile 缺少 USER 指令」这一文件级事实，
        # 因此 pattern 只锚定 FROM 行、由 suppress_if 在文件中出现任意 USER 指令时整条豁免。
        # 不检测 USER root（语义即显式声明，属运维决策），避免对合规文件误报。
        "id": "CFG-DOCKER-001",
        "title": "Dockerfile 未声明非 root 运行用户",
        "severity": "medium",
        "category": "config",
        "languages": ["dockerfile"],
        "pattern": r"""(?i)^\s*FROM\s+\S+""",
        "excludes": [],
        "suppress_if": r"""(?im)^\s*USER\s+\S+""",
        "path_exclude": r"(?i)(node_modules/)",
        "description": "整个 Dockerfile 未出现任何 USER 指令，容器内进程将以默认的 root 运行。一旦容器被突破，攻击者直接获得 root 身份，更容易逃逸到宿主机或横向移动。",
        "remediation": "在 Dockerfile 末尾添加非特权用户：\n  RUN addgroup -S app && adduser -S -G app app\n  USER app\n并配合 runAsNonRoot: true（K8s）、--read-only、drop ALL capabilities。",
        "cwe": "CWE-250",
        "confidence": "medium",
        "references": ["https://cwe.mitre.org/data/definitions/250.html"],
    },
    {
        "id": "CFG-K8S-001",
        "title": "容器以特权模式运行 / 危险能力",
        "severity": "high",
        "category": "config",
        "languages": ["yaml", "json"],
        "pattern": r"""(?i)(privileged\s*:\s*true|allowPrivilegeEscalation\s*:\s*true|hostNetwork\s*:\s*true|hostPID\s*:\s*true|hostPath\s*:|SYS_ADMIN|NET_ADMIN|hostIPC\s*:\s*true)""",
        "description": "Kubernetes/Compose 配置开启 privileged、hostNetwork、hostPath 或授予 SYS_ADMIN，容器可获得宿主机级权限，极易被用于逃逸与横向移动。",
        "remediation": "移除 privileged: true；\n设置 allowPrivilegeEscalation: false；\ncapabilities: drop: [\"ALL\"] 后按需最小化添加；\n用只读根文件系统与 seccomp/AppArmor 配置收敛权限。",
        "cwe": "CWE-250",
        "confidence": "high",
        "references": ["https://cwe.mitre.org/data/definitions/250.html"],
    },
    {
        "id": "CFG-TF-001",
        "title": "Terraform 资源对公网开放",
        "severity": "high",
        "category": "config",
        "languages": ["terraform"],
        "pattern": r"""(?i)(cidr_blocks?\s*=\s*\[\s*["']0\.0\.0\.0/0["']|acl\s*=\s*["']public-read|publicly_accessible\s*=\s*true|block_public_acls\s*=\s*false|block_public_policy\s*=\s*false|ignore_public_acls\s*=\s*true|restrict_public_buckets\s*=\s*false|encrypted\s*=\s*false|storage_encrypted\s*=\s*false)""",
        "description": "基础设施即代码中把安全组/存储桶/数据库暴露到 0.0.0.0/0 或关闭加密，云上资产会直接暴露在互联网，是最常见的云泄露根因。",
        "remediation": "安全组入站收敛到具体办公/业务网段 CIDR；\n存储桶默认私有并开启 public access block；\n数据库启用静态加密（storage_encrypted / encrypted = true）与私有子网部署。",
        "cwe": "CWE-284",
        "confidence": "high",
        "references": ["https://cwe.mitre.org/data/definitions/284.html"],
    },
    {
        "id": "CFG-CI-001",
        "title": "CI/CD 工作流中明文密钥",
        "severity": "high",
        "category": "config",
        "languages": ["yaml"],
        "pattern": r"""(?i)^\s{2,}(password|token|secret|api[_-]?key|access[_-]?key|private[_-]?key)\s*:\s*\S{6,}""",
        "excludes": [r"(?i)(\$\{\{|secrets\.|vault|env\.|\*{3,}|<[^>]+>)"],
        "path_exclude": r"(?i)(node_modules/|/testdata/)",
        "description": "流水线配置中直接写入密钥，仓库或日志泄露即可触发供应链攻击（可篡改构建产物、推送后门）。",
        "remediation": "改为引用平台密钥库：\n  ${{ secrets.PROD_TOKEN }}\n开启密钥掩码、限制 PR 触发权限、对第三方 Action 固定 commit SHA 并做签名校验（如 zizmor）。",
        "cwe": "CWE-798",
        "confidence": "medium",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    {
        "id": "CFG-DEPS-001",
        "title": "依赖版本未锁定或使用 latest",
        "severity": "low",
        "category": "config",
        "languages": ["dockerfile"],
        "pattern": r"""(?i)^\s*FROM\s+\S+:(latest|stable|main|master)\s*$""",
        "description": "基础镜像使用 latest 等浮动标签，构建结果不可重现，且可能在不知情时引入带漏洞的新版本。",
        "remediation": "固定镜像摘要：\n  FROM alpine:3.20@sha256:xxxx\n并接入镜像漏洞扫描（如 Trivy）到 CI 门禁。",
        "cwe": "CWE-1104",
        "confidence": "high",
        "references": ["https://cwe.mitre.org/data/definitions/1104.html"],
    },
    {
        "id": "CFG-REGEX-001",
        "title": "存在 ReDoS 风险的正则表达式",
        "severity": "medium",
        "category": "config",
        "languages": ["go", "python", "javascript", "java", "php", "ruby"],
        "pattern": r"""(?i)(MustCompile|regexp\.Compile|\bre\.compile|new\s+RegExp|re\.match|preg_match)\s*\(\s*[^)\n]*\([^)\n]*[*+][^)\n]*\)[*+][^)\n]*""",
        "description": "正则中存在嵌套量词（如 (a+)+），对特定构造的输入会引发灾难性回溯（指数级耗时），造成 CPU 打满、服务不可用。",
        "remediation": "重构正则避免嵌套量词与重叠分支；\n为匹配设置长度上限与超时；\n使用 RE2 引擎（Go regexp 已基于 RE2，但在 .NET/JS/Java 中需特别注意），必要时对输入做长度限制。",
        "cwe": "CWE-1333",
        "confidence": "low",
        "references": ["https://cwe.mitre.org/data/definitions/1333.html"],
    },

    # =====================================================================
    # 十、代码质量风险（可演化成安全问题）
    # =====================================================================
    {
        "id": "QUA-ERR-001",
        "title": "错误返回值被静默忽略",
        "severity": "medium",
        "category": "quality",
        "languages": ["go"],
        "pattern": r"""(?m)^\s*(?:[a-zA-Z_][\w.]*\s*,\s*)?_\s*(?:,\s*[a-zA-Z_]\w*\s*)?:?=\s*(?:\w+\.)?\w+\s*\(""",
        "excludes": [r"^\s*(//|/\*)", r"(?i)(range|_,\s*ok|_,\s*err\s*:=)"],
        "path_exclude": r"(?i)(_test\.go|/testdata/)",
        "description": "使用 _ 丢弃函数返回的 error，失败路径不再被处理，可能导致资源未释放、状态不一致，甚至把错误当成成功继续执行（如漏检、鉴权被跳过）。",
        "remediation": "不要丢弃 error：\n  if err := f(); err != nil { return err }\n确需忽略时显式注释说明原因（如 defer x.Close() 的场景）。",
        "cwe": "CWE-391",
        "confidence": "low",
        "references": ["https://cwe.mitre.org/data/definitions/391.html"],
    },
    {
        "id": "QUA-PANIC-001",
        "title": "使用 panic 处理可恢复错误",
        "severity": "medium",
        "category": "quality",
        "languages": ["go"],
        "pattern": r"""(?m)^\s*panic\s*\(""",
        "excludes": [r"^\s*(//|/\*)", r"panic\(\s*\"(unreachable|not implemented)"],
        "path_exclude": r"(?i)(_test\.go|/testdata/|/mocks?/)",
        "description": "在库代码或请求处理路径中直接 panic，会终止当前 goroutine；若未被 recover 捕获将导致整个服务崩溃（拒绝服务）。",
        "remediation": "把 panic 改为返回 error 并向上传播；\n在 HTTP 中间件/goroutine 入口统一 recover 并记录堆栈；\n仅在初始化阶段（不可恢复配置错误）使用 panic。",
        "cwe": "CWE-248",
        "confidence": "medium",
        "references": ["https://cwe.mitre.org/data/definitions/248.html"],
    },
    {
        "id": "QUA-RES-001",
        "title": "文件/连接打开后未见关闭",
        "severity": "low",
        "category": "quality",
        "languages": ["go", "python", "java", "javascript"],
        "pattern": r"""(?i)(os\.Open\s*\(|os\.Create\s*\(|net\.Dial\w*\s*\(|sql\.Open\s*\(|open\s*\(|Files\.newInputStream|new\s+FileInputStream|fs\.openSync)""",
        "excludes": [r"(?i)(defer\s+\w+\.Close|with\s+open|\.close\s*\(|Close\(\)|using\s*\()"],
        "guard": {"window": 12, "pattern": r"(?i)(defer\s+\w+\.Close|defer\s+func|with\s+open|\.close\s*\(|Close\(\))"},
        "description": "打开了文件、连接或数据库句柄但没有对应的 Close，长时间运行会耗尽文件描述符/连接池，最终导致服务不可用。",
        "remediation": "打开后立即 defer 关闭：\n  f, err := os.Open(path)\n  if err != nil { return err }\n  defer f.Close()\nPython 使用 with open(...) as f: 上下文管理器。",
        "cwe": "CWE-404",
        "confidence": "low",
        "references": ["https://cwe.mitre.org/data/definitions/404.html"],
    },
    {
        "id": "QUA-CTX-001",
        "title": "请求链路中使用无超时的后台 Context",
        "severity": "low",
        "category": "quality",
        "languages": ["go"],
        "pattern": r"""(?i)context\.(Background|TODO)\s*\(\s*\)""",
        "excludes": [r"^\s*(//|/\*)"],
        "path_exclude": r"(?i)(_test\.go|/testdata/|/examples?/|/e2e/)",
        "description": "在请求处理链路中新建 context.Background()/TODO() 会切断超时与取消传播，下游阻塞将拖垮整个服务。",
        "remediation": "从上游继承并设置超时：\n  ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)\n  defer cancel()\n仅在最外层（main/初始化）使用 context.Background()。",
        "cwe": "CWE-400",
        "confidence": "low",
        "references": ["https://cwe.mitre.org/data/definitions/400.html"],
    },
    {
        "id": "QUA-HTTP-001",
        "title": "HTTP 服务未设置读写超时",
        "severity": "medium",
        "category": "quality",
        "languages": ["go"],
        "pattern": r"""(?i)(http\.(Server|Client)\s*\{|http\.DefaultClient|&http\.Client\s*\{)""",
        "excludes": [r"(?i)(Timeout|ReadTimeout|WriteTimeout|IdleTimeout|ReadHeaderTimeout)\s*:"],
        "guard": {"window": 12, "pattern": r"(?i)(ReadTimeout|WriteTimeout|IdleTimeout|ReadHeaderTimeout|Timeout)\s*:"},
        "description": "http.Server/Client 未配置超时参数，慢连接（Slowloris）即可长期占用连接与 goroutine，造成资源耗尽型拒绝服务。",
        "remediation": "显式配置超时：\n  srv := &http.Server{\n      ReadHeaderTimeout: 5 * time.Second,\n      ReadTimeout:       15 * time.Second,\n      WriteTimeout:      15 * time.Second,\n      IdleTimeout:       60 * time.Second,\n  }\nClient 侧同样设置 Timeout 与 Transport 超时。",
        "cwe": "CWE-400",
        "confidence": "medium",
        "references": ["https://cwe.mitre.org/data/definitions/400.html"],
    },
    {
        "id": "QUA-TODO-001",
        "title": "遗留 TODO/FIXME 安全标记",
        "severity": "info",
        "category": "quality",
        "languages": ["*"],
        "pattern": r"""(?i)(TODO|FIXME)[:\s][^\n]{0,80}(sanitiz|escap|inject|unsafe|bypass|vulnerab|privilege\s*escalat|no\s*validat|without\s*validat|missing\s*(auth|check|valid))""",
        "description": "代码中遗留安全相关的 TODO/FIXME 注释，说明已知风险点尚未闭环，建议纳入缺陷跟踪系统统一管理。（刻意不匹配 XXX/HACK 等泛用标记，避免把「临时方案」注释误报为安全待办。）",
        "remediation": "将此类注释登记为安全缺陷工单，明确责任人与修复期限，并在 CI 中加入标记数量趋势监控。",
        "cwe": "CWE-1059",
        "confidence": "low",
        "references": ["https://cwe.mitre.org/data/definitions/1059.html"],
    },
]


def get_rule_index():
    """返回 {rule_id: rule} 索引，便于查找。"""
    return {r["id"]: r for r in RULES}
