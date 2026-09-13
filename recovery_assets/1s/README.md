# 1S 构建输入

这些文件是完整镜像生成和测试所必需的输入，不作为独立下载成品。

| 文件 | 来源 | 字节数 | SHA-256 |
| --- | --- | --- | --- |
| `DRV319-stock.bin` | [ScooterHacking 普通 3.1.9](https://firmware.scooterhacking.org/1s/DRV/3.1.9.bin) | 28148 | `c983d44ab7c68ff4c7b72e09ec7b862b009e00e8b2105a5f0a33bfc85b152387` |
| `boot.bin` | CamiAlfa `boot.bin` | 3104 | `7f5574cb1233653db95e8cc4baf2b99f446ffb973e01651cde190f013262016a` |
| `data-template.bin` | CamiAlfa `data.bin` | 512 | `4385da291edd2284fadd9d055ee182d2f22bb36efd28f27946206162d43d3ce6` |

引导程序和数据模板来自 [CamiAlfa/M365_DRV_STLINK 固定版本](https://github.com/CamiAlfa/M365_DRV_STLINK/tree/b4e03683d5f9fe6981a615855e2e3d34c36ab844)，
原字节保留。构建布局及 UID/SN/里程字段依据该项目的 `flash_m365_1S.py`，其脚本含 GPLv3-or-later 声明。

车辆数据模板必须填入目标主板的 UID 和明确选择的序列号。它不能找回已擦除的原始设置。
使用 [完整镜像生成器](../../build_1s_recovery.py)，参见 [使用说明](../../docs/1s-drv319-nobms.md)。
