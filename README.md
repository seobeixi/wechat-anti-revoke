# 微信防撤回补丁 · 通用自适应引擎

一个 Python 脚本，给 Windows 微信打防撤回补丁，并且**尽量适配任意版本**——微信升级后不用干等工具更新，它自己会重新找位置。

## 它解决什么问题

现成的补丁工具（比如 RevokeMsgPatcher）是按版本区间写死特征码的。微信一升级，特征码变了，就只能等作者发新版本。

这个脚本的思路不同：**用多级降级匹配 + 反汇编校验，自动重新定位补丁点。**

## 和 RevokeMsgPatcher 的关系（先说清楚）

**底层特征码数据来自 [RevokeMsgPatcher](https://github.com/huiyadanli/RevokeMsgPatcher) 的在线补丁库。** 本项目没有自己独立的逆向成果，那部分是人家的。

本项目自己写的部分：

- **自适应匹配层**：多级降级，容差上限卡在 1 字节
- **安全校验层**：`.text` 段校验、反汇编指令边界校验、唯一性硬要求、写前逐字节核对
- **自动化层**：定时任务、状态跟踪、已打过识别、自动备份还原

简单说：**规则是借的，工程是自研的。**

## 实测数据：容差黄金线

在微信 4.1.15.13（`Weixin.dll`，192 MB）上实测：

| 允许几个字节不同 | 匹配到几处 |
|---|---|
| 0 字节 | 1 处 |
| **1 字节** | **1 处** ← 黄金线 |
| 2 字节 | 5 处（开始歧义）|
| 3 字节 | 37 处（不可用）|

所以引擎的容差**硬性卡在 1，永不越过**。多放宽一格就会误伤。

## 多级降级机制

| 等级 | 做法 | 置信度 |
|---|---|---|
| L0 | 用补丁后特征反查，识别"已打过" | HIGH |
| L1 | 精确匹配（容差 0），唯一命中 | HIGH |
| L2 | 容差 1 + 必须在 `.text` + 反汇编指令边界校验 | MEDIUM_HIGH |
| L3 | 特征侵蚀：长特征拆锚点重新定位 | MEDIUM |
| L4 | 结构推导（`revokemsg` 协议表 + 指令模式） | LOW（**仅报告，不写入**）|

**LOW 置信度一律拒绝写入**，宁可不动，不瞎改。

## 使用

需要 Python 3.8+，依赖 `pefile` 和 `capstone`。

```bash
pip install pefile capstone
```

```bash
# 看本机装了哪些微信、版本多少、能否支持
python wechat_universal.py scan

# 只体检，不改文件
python wechat_universal.py check

# 打补丁（需先完全退出微信）
python wechat_universal.py apply

# 顺带多开
python wechat_universal.py apply --multi

# 只看会改什么，不实际写
python wechat_universal.py apply --dry

# 还原
python wechat_universal.py restore

# 自动模式（供定时任务用）：已打过就跳过，微信在跑就等下一轮
python wechat_universal.py auto --quiet
```

## 兼容范围

- **微信 4.x**：核心文件 `Weixin.dll`
- **微信 3.x**：核心文件 `WeChatWin.dll`
- 自动扫描 `C`~`H` 盘常见安装位置，支持子目录版和同层版布局

## 安全设计

- 改动前自动备份为 `.bak`
- 写入前逐字节核对原值，不符立即中止
- 多处命中一律放弃（防误伤）
- 只在 `.text` 代码段写入
- 反汇编校验，确认落在合法指令边界
- 每次只改 1~2 个字节

## 已知限制

- **仅本机生效**：撤回在服务器上依然成功，只是你本地记录不消失
- **手机端不适用**
- **微信大版本重构可能失效**：这时脚本会报告"定位失败"而不是瞎改
- 改客户端本地文件属非官方修改，**理论上有账号风控风险**，工作号/客户号请自行权衡

## ⚠️ 免责声明

本项目仅供**个人学习、研究与技术交流**使用。

- 请仅用于处理**你自己合法拥有**的设备与数据
- 使用者须自行承担因使用本工具产生的一切后果
- 请遵守当地法律法规及软件服务条款
- 作者不对任何直接或间接损失负责

**下载或使用本项目，即表示你已阅读并同意上述条款。**

## 授权

本项目采用 **GPL-3.0** 协议 —— 与上游数据来源 RevokeMsgPatcher 保持一致。

## 致谢

- [RevokeMsgPatcher](https://github.com/huiyadanli/RevokeMsgPatcher) —— 提供补丁规则库与逆向成果
- [pefile](https://github.com/erocarrera/pefile) / [capstone](https://github.com/capstone-engine/capstone) —— PE 解析与反汇编
