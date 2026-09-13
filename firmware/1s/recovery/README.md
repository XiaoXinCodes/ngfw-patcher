# 已实车确认的 1S 完整镜像

用户确认 [DRV319-BMSREAD-FULL-EXPERIMENTAL.bin](DRV319-BMSREAD-FULL-EXPERIMENTAL.bin) 可用。

- **烧录起始地址：`0x08000000`**。
- 大小：65536 字节，包含 Bootloader、应用和车辆数据。
- SHA-256：`d38dac82b58e9f98973fde46b912191839f6635e86775e1072255e05ccef57d9`。
- UID：`066FFF57 48557886 67092140`。
- 替代序列号：`25699/38039257`；里程恢复为 0；电量固定显示 80%。

[校验与补丁报告](DRV319-BMSREAD-FULL-EXPERIMENTAL.bin.json) · [烧录与重建说明](../../../docs/1s-drv319-nobms.md)

该文件针对上述主板个性化；其他主板须用自己的 UID 重建。用户反馈为单车确认，
不是对所有硬件组合的验证。文件名保留不变，二进制内容没有因整理而改变。
