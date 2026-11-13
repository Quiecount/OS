# AGENTS.md — 仓库协作规范（团队成员与 AI 助手通用）

> 本文件面向两类读者：本仓库的团队成员，以及任何在此仓库中工作的 AI 编程助手。
> 任何 AI 助手在被要求修改本仓库前，**必须先完整阅读本文件**，并遵守 §8 的行为指令。

---

## 1. 项目事实速览

| 项 | 值 |
|---|---|
| 项目 | 太卡了先生——基于 eBPF 的 openEuler 系统异常观测与根因定位工具（工作代号 osmedic） |
| 队伍名称 | 太卡了先生（GitLab 项目名称格式：系统工具-太卡了先生） |
| 选题方向 | 系统工具（OS 应用开发赛道·方向一） |
| 目标赛事 | 全国大学生计算机系统能力大赛·操作系统设计赛华东区域赛·OS 应用开发赛道 |
| 运行环境 | openEuler 24.03 LTS（内核 6.6，x86_64）；后期适配 openEuler 22.03（内核 5.10）与 ARM64 |
| 技术栈 | eBPF 探针（C + libbpf）｜聚合与规则诊断引擎（Python）｜LLM 报告层（HTTP 调用 API） |
| 当前阶段 | 阶段 0：环境搭建（详见 `docs/开发计划_eBPF异常观测与根因定位工具.md` §五） |
| 仓库性质 | 比赛过程性资料的一部分：**提交历史 = 评分项，不可篡改** |

## 2. 仓库结构与文件归置规则

```
docs/          # 项目文档：选题分析 / eBPF入门与获奖案例 / 开发计划 / 团队环境指南
src/           # （规划中）eBPF 探针源码（*.bpf.c）与用户态 C 加载器
analysis/      # （规划中）Python：聚合、基线、规则诊断引擎
report/        # （规划中）Python：LLM 报告层（必须带 --no-llm 降级开关）
faults/        # （规划中）5 类异常场景的故障注入脚本/程序
tests/         # （规划中）自动化测试、场景回放、PASS/FAIL 判分脚本
deploy.sh      # （规划中）一键部署
test.sh        # （规划中）一键测试
```

**归置规则（AI 生成代码时必须遵守）**：

| 要写入的文件类型 | 必须放在 |
|---|---|
| eBPF 探针程序（`*.bpf.c`） | `src/probes/` |
| 用户态 C 加载器 | `src/loader/` |
| 聚合 / 基线 / 规则诊断逻辑 | `analysis/` |
| LLM 报告生成逻辑 | `report/` |
| 故障注入程序与脚本 | `faults/`（按场景命名，如 `faults/01_syscall/`） |
| 测试与回放脚本 | `tests/` |
| 文档 | `docs/` |
| 临时脚本 / 二进制产物 | **禁止提交** |

## 3. 分支模型

| 分支 | 负责人 | 用途 | 谁可以直接 push |
|---|---|---|---|
| `main` | quiecount（仓库 owner） | 稳定主干；比赛最终提交源；文档 | quiecount |
| `dev/mao` | mao | mao 的日常开发分支 | mao |
| `dev/yu` | yu | yu 的日常开发分支 | yu |

**规则**：

1. mao、yu 的改动一律先进个人分支，**不得直接 push main**
2. quiecount（owner）可直接提交 main（如文档更新）
3. 每日收工由 owner 将 `dev/*` 合并进 `main`（合并前确认无冲突）
4. 个人分支需随时同步 main 的最新进度（命令见 §4.2）

## 4. 命令模板（按场景复制执行）

### 4.1 首次克隆（新机器 / 新队友）

```bash
git clone https://github.com/Quiecount/OS.git
cd OS
git checkout dev/mao        # mao 用 dev/mao；yu 用 dev/yu
```

### 4.2 每日开始（先同步主干进度）

```bash
git checkout main
git pull
git checkout dev/mao        # 回到自己的分支
git merge main              # 把主干新进展合进来；无冲突即完成
```

### 4.3 提交（任意时刻）

```bash
git status                  # 先看改了什么
git add <文件>               # 或 git add . 全部暂存
git commit -m "feat: 一句话说清这次改了什么"
```

### 4.4 推送个人分支（每天至少一次）

```bash
git push                    # 已设好上游分支；若首次推送失败改用：
git push -u origin dev/mao
```

### 4.5 合并到 main（仅 owner 执行；main 必须双推）

```bash
git checkout main
git pull
git merge dev/mao
git merge dev/yu
git push origin main         # ① GitHub（开发主仓）
git push gitlab main         # ② educg GitLab（比赛官方仓，提交记录 = 过程性资料）
```

**两个远程的分工**：

| remote 名 | 指向 | 用途 |
|---|---|---|
| `origin` | https://github.com/Quiecount/OS.git | 开发主仓：日常开发、分支、协作 |
| `gitlab` | https://gitlab.eduxiji.net/T2026103369913109/project3331747-425741.git | **比赛官方提交仓**：main 每次更新都要同步推过去 |

> 注：GitLab 项目在网页上改名为"系统工具-太卡了先生"后，其 URL 会变化，owner 需执行 `git remote set-url gitlab <新地址>` 更新。

## 5. 提交信息规范

- 格式：`类型: 摘要`，类型 ∈ {feat, fix, docs, test, chore}
- 摘要用中文或英文均可，一行 ≤ 50 字
- 一次提交只做一件事（探针一个 commit、文档一个 commit）
- 示例：`feat: 场景1 syscall 探针（计数+延迟直方图）`、`docs: 补充场景3 IO 延迟的 map 结构说明`

## 6. 红线（任何情况下不得违反）

1. **禁止 `git push --force` 到 main**——提交记录是比赛评分项"过程性资料"，历史不可篡改
2. 禁止提交：虚拟机镜像/磁盘文件、ISO、大二进制、`CODELY.md`、`.codely-cli/`（`.gitignore` 已排除，不得改动这些排除项）
3. mao / yu 禁止绕过个人分支直接修改 main
4. 冲突解不动时：停止操作，联系 owner 手工处理；**禁止用"覆盖对方文件"的方式解决冲突**

## 7. 出错速查表

| 症状 | 处理 |
|---|---|
| push 被拒（non-fast-forward） | `git pull --rebase` 后再 `git push` |
| 合并冲突 | `git status` 找冲突文件 → 手工编辑 `<<<<<<< ======= >>>>>>>` 之间的内容 → `git add <文件>` → `git commit` |
| 不小心在 main 上改了代码（mao/yu） | `git checkout -b dev/mao` 把改动带进个人分支，再提交推送；main 上的改动不 push |
| 想丢弃某个文件未提交的修改 | `git checkout -- <文件>`（**不可逆**，执行前确认） |
| 想看自己/队友的提交历史 | `git log --oneline` / 在 GitHub 仓库页面的分支菜单切换查看 |

## 8. 给 AI 助手的行为指令（重要）

**如果读到这里的是 AI 编程助手**，在被要求对本仓库工作时，必须遵守：

1. **文件归置**：生成的每个文件必须放进 §2 表格指定的目录；新建目录需与 §2 规划一致。
2. **分支安全**：修改与提交前，确认当前分支是用户的个人分支（`dev/mao` 或 `dev/yu`）。除非用户明确声明自己是 quiecount（owner），否则**不得向 `main` 提交任何内容**。
3. **提交规范**：commit message 遵循 §5；不使用 `--force`；不执行 §6 红线中的任何操作。
4. **技术依据**：探针挂载点选型、五场景指标与规则、JSON 输出契约、阶段划分，一律以 `docs/开发计划_eBPF异常观测与根因定位工具.md` 为准；本文件与 docs/ 冲突时以 docs/ 为准，并提醒用户更新本文件。
5. **eBPF 代码约束**：探针程序必须在 Verifier 约束下可通过（无任意循环、栈 ≤512 字节、只调用内核 helper 函数）；复杂逻辑放在用户态，探针只做采集。
6. **运行环境**：编译与测试发生在 openEuler 24.03（本机 Hyper-V 虚拟机或 SSH 远程环境，内核 6.6）；Windows 本机不编译 eBPF；开发环境细节见 `docs/团队开发环境搭建指南.md`。
7. **阶段相关**：只生成与当前阶段相关的代码（当前阶段 0 = 环境搭建与工具链验证；阶段任务清单见 docs/开发计划 §五）。用户要求超前实现时，先提醒阶段规划再执行。
8. **语言**：代码注释与文档使用中文或英文均可；与用户沟通跟随用户语言。

## 9. 状态快照（owner 维护，AI 以此为准）

- 2026-11-08：仓库建立；`docs/` 收录 4 份文档；分支 main / dev/mao / dev/yu；阶段 0（环境搭建）进行中，尚无代码
- 2026-11-08：队名定为「太卡了先生」；README 按大赛提交要求改版（报名信息 + 项目名称 + 题目内容）
- 2026-11-13：main 已推送至 educg GitLab（remote：`gitlab`，当前项目名 project3331747-425741）；**待办**：GitLab 网页改项目名为"系统工具-太卡了先生"并更新 remote 地址、README 回填高校/队伍ID/队员信息
