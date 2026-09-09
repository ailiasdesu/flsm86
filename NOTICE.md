# 来源与合规说明

## 上游

- 上游项目：https://github.com/sdli1995/dlssg_for_sm86
- 上游仓库**没有 LICENSE 文件**（GitHub API `license: null`）。
- 上游 `THIRD_PARTY_NOTICES.txt` 自述：*"Project source follows the dlssg-to-fsr3 repository's GPLv3 license (LICENSE.md)"*，
  但仓库中并不存在该 `LICENSE.md`。
- 同文件明确：*"The NVIDIA runtime DLL and extracted/recompiled NVIDIA kernel assets are separate third-party material … they are not relicensed by LICENSE.md."*

## 本仓库的取舍

| 内容 | 是否包含 | 说明 |
|---|---|---|
| 本注入器源码 | ✅ | GPL-3.0-or-later（与上游声明的许可一致） |
| 上游的 `version.dll` | ❌ | 内含 NVIDIA 运行时与重编译内核，**不受**上游许可覆盖，不得再分发 |
| `nvngx_dlssg.dll` / CUDA 内核 | ❌ | 同上 |
| 使用者自备载荷 | — | 通过 `--pack` 生成加密载荷，仅存于本机 |

## 第三方

- Microsoft Detours / d3dx12.h / JSON for Modern C++（上游使用的 MIT 组件）——本仓库不包含其代码。
- 本项目仅实现**注入与加载**，不含任何 NVIDIA 代码。
