# LOVEBIND

[![MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

如果项目需要使用[text_hook](https://github.com/renamed23/translate-tools)，请设置环境变量`TEXT_HOOK_PROJECT_PATH`为`text_hook`的绝对路径，并确保已安装rust工具链(stable+nightly>=1.93.0)

```cmd
set TEXT_HOOK_PROJECT_PATH=C:\path\to\text_hook
```

```powershell
$env:TEXT_HOOK_PROJECT_PATH = "C:\path\to\text_hook"
```

使用 `python start.py e` 提取原文到 `raw.json`

使用 `python start.py r` 根据译文 `translated.json` 生成翻译补丁文件

生成的翻译补丁文件在`generated/dist`，一般可直接复制到游戏目录
