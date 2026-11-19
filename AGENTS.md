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
docs/          # 项目文档：选题分析 / 开发计划 / 系统设计 / 环境指南 / 各阶段开发指南
src/           # 探针（probes/：execsnoop 完整 + 5 场景骨架）+ 加载器（loader/）+ 事件契约（events.h）；vmlinux.h 由 make 自动生成、不入库
analysis/      # Python：聚合、基线、规则诊断引擎（骨架 collector.py，阶段 3 完成规则引擎）
report/        # Python：LLM 报告层（阶段 4 建，必须带 --no-llm 降级开关）
faults/        # 五场景故障注入：01-05 脚本 + syscall_bomb.c / lock_contention.c
tests/         # test.sh 一键回归（阶段 3 接入自动判定）
deploy.sh      # 一键部署（装依赖 + make）
test.sh        # 一键测试入口（转调 tests/test.sh）
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

### 4.5 合并到 main（仅 owner 执行）

```bash
git checkout main
git pull gitlab main         # 先拉：GitLab 网页端也可能被直接编辑过（2026-11-13 已发生过）
git merge dev/mao
git merge dev/yu
git push gitlab main         # 必推：educg GitLab = 比赛官方仓，提交记录就是过程性资料
git push origin main         # 尽力推：GitHub 镜像；网络不通就跳过，恢复后补推，禁止反复重试
```

**两个远程的分工**：

| remote 名 | 指向 | 用途 |
|---|---|---|
| `gitlab` | https://gitlab.eduxiji.net/T2026103369913109/project3331747-425741.git | **比赛官方提交仓（必推）** |
| `origin` | https://github.com/Quiecount/OS.git | GitHub 镜像（尽力同步；2026-11-13 起网络不稳，允许滞后） |

> 注 1：GitLab 项目在网页上改名为"系统工具-太卡了先生"后，其 URL 会变化，owner 需执行 `git remote set-url gitlab <新地址>` 更新。
> 注 2：**不要在 GitLab 网页端直接编辑文件**——会产生本地没有的提交导致推送被拒；文件编辑一律在本地做，GitLab 网页只用来改名、看提交记录。

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
- 2026-11-13：main 已推送至 educg GitLab（remote：`gitlab`，当前项目名 project3331747-425741）；**待办**：GitLab 网页改项目名为"系统工具-太卡了先生"并更新 remote 地址
- 2026-11-13：README 报名信息定稿——高校：杭州电子科技大学；队伍ID：T2026103369913109；按要求删除项目名称/选题方向/队员/指导教师行（标题即项目名称）
- 2026-11-13：第一支探针 execsnoop 完成——src/probes + src/loader + src/event.h + Makefile + docs/开发指南；VM 内构建 = 仓库根目录 `make`（自动生成 src/vmlinux.h），运行 = `sudo ./build/execsnoop`；GitHub 同步暂缓（网络不稳），main 只推 gitlab
- 2026-11-18：五场景总体框架落地——src/events.h 统一事件契约（execsnoop 已重构接入，旧 event.h 删除）；5 个场景探针骨架（syscall/cpu/io/mem/lock，可编译、指标 TODO 见各文件与系统设计文档 §四）；faults 注入全套（01-05 脚本 + syscall_bomb + lock_contention）；analysis/collector.py、deploy.sh、test.sh 骨架；总体设计见 docs/系统设计_五场景总体框架.md。**GitLab 推送暂停中（用户要求本地攒批，等指令恢复）**
- 2026-11-18：接口契约 v1.0 定稿（docs/接口契约.md）——六条接缝的输入/输出成文：JSONL 格式（stdout 纯 JSONL/提示走 stderr）、地址字段 hex 字符串防精度丢失、七字段报告 schema、异常类型枚举与 key_metrics 键名表；execsnoop 加载器 JSONL 迁移列为阶段 2 技术债。推送已恢复，攒批提交已全部推上 GitLab
- 2026-11-18：**开发计划压缩改版——冲刺终线改为 12/15**（原 1/4），27 天 4 周冲刺：验证收口 3 天→场景 1-3 十一天→场景 4-5 五天→诊断引擎 3 天→LLM 2 天→收尾 2 天→缓冲 2 天；12/16-01/04 变打磨期（多平台等增量）；砍单顺序改为：LLM→场景5进阶指标→场景5。详见开发计划 §二/§五
