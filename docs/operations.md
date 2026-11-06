# 部署、验证和回滚

## 首次部署前

1. 确认可以通过管理网或独立有线 SSH 进入**目标机器人**，记录设备身份。软件不更改办公 WiFi SSID、密码或 IPv6。
2. `ip -4 -br a`、`ip -4 route`、`nmcli con show --active`，辨认实际接口，不能把网口外壳编号当 Linux 名称。
3. 规划两段互不重叠的 IPv4 地址。机器人 `.10.200` 应在底盘 DHCP 池外；`.66.10` 做地址保留。工具在新赋值前做 ARP 探测，但管理员仍须核对静态设备列表。
4. 现场检查 5G 路由器不启用热点客户端隔离，LAN 允许访问有线机器人。新增 `.10.0/24 → .66.10 / LAN` 静态路由和 eth0 地址保留。不要修改蜂窝 APN、SIM 白名单或底盘 VLAN 来试运气。
5. 通过可信渠道核对 SSH 主机指纹。在设备本机可执行 `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256`；旧设备按实际 key 类型执行。`ssh-keyscan` 单独抓到的值不构成身份验证。配置支持可选 `host_key_type`，例如 `ecdsa-sha2-nistp256`，选择对应已核对的密钥算法。

默认 JSON 的 `test_client` 为空。若需要真实热点测试，把它改为：

```json
{
  "host": "测试机可达的管理IP",
  "username": "测试机用户",
  "host_key_sha256": "SHA256:已核对值",
  "host_key_type": "ssh-ed25519",
  "interface": "wlan0",
  "source_ip": "操作电脑有线源IP（不需要时删除本项）"
}
```

上面是 `test_client` 字段的内容，其他字段保留。远端测试 HTTP 绑定 wlan0；管理连接可以走独立有线。真实客户端的地址会随 DHCP 改变，以现场状态为准。

## 一键命令

```bash
./optimize.sh --config site.local.json          # 预演
./optimize.sh --config site.local.json --apply  # 备份、变更、验收、确认
./test.sh --config site.local.json --samples 5 # 默认只读测试
```

终端摘要里的 `changed: false` 对 test 命令表示未进行配置优化，不代表所有测试通过；要看 checks 和退出码。配置的测试客户端为空时，报告中不会出现客户端验收项。JSON 原始报告可查看每次请求的源 IP、目的 IP、HTTP 码和延时。

不要只凭脚本退出成功就宣称一切完成：test 会检查最新底盘诊断的 internet 与 DNS 状态。历史累计成功率不会因修复归零。HTTP 根路径 200 与业务端点 404 的含义不同：底盘网页期望 200，语音平台根路径只用来验证网络/TLS，有响应不等于鉴权成功。

## 手工排障：从近到远

机器人执行：

```bash
ip -4 -br address
ip -4 route
ip -4 route get 223.5.5.5
nmcli -g GENERAL.CONNECTION,IP4.ADDRESS,IP4.GATEWAY device show eth1
sysctl net.ipv4.ip_forward
sudo nft list table ip robot_chassis_access
sudo nft list table ip robot_chassis_return_path
ip -4 rule show
ip -4 route show table 16600
curl --noproxy '*' --max-time 5 -I http://192.168.10.10:9001/
systemctl is-active robot-chassis-access.service \
  robot-chassis-return-path.service robot-chassis-return-path.timer \
  robot-network-health.timer
cat /run/robot-network-health.json
journalctl -u robot-network-health.service -n 30 --no-pager
```

热点测试设备执行：

```bash
ip -4 -br address
ip -4 route
curl --noproxy '*' --interface wlan0 --max-time 8 \
  -sS -o /dev/null -w '%{http_code}\n' http://192.168.10.10:9001/
```

底盘路由器只读查看（SSH root，密码交互输入）：

```sh
uci get network.lan.gateway
uci get network.lan.dns
uci get wireless.radio0.disabled
uci get wireless.radio1.disabled
ip -4 route
```

预期分别为 `.10.200`、配置 DNS、`1`、`1`，实际默认路由应指向 `.10.200`。只保存 UCI 而未更新实际路由，并不算已生效。

## 出口演练

维护窗口执行 `./test.sh --config site.local.json --exercise-failover --samples 3`。报告中 `controlled_switch.cellular` 和 `.wifi` 分别保存两条路径，检查 `requested_egress_selected`。完成后恢复原 active 状态并重新启用健康定时器。

它是受控路由切换，不是把真实 WiFi 上游断开的故障注入；3 轮故障、6 轮恢复和 120 秒等待另有状态机测试。要证明真实自动恢复时间，应在有人值守和有独立管理路径的条件下做物理断网演练，并记录应用重连时间。不要在正在执行运动或通话任务时随意拔线。

## 备份和回滚

机器人：`/var/backups/robot-network-toolkit/<事务号>/`，含持久 NM 配置、实际生效配置、工具拥有的文件、unit 状态和 `rollback.sh`。底盘路由器：`/root/robot-network-backups/<事务号>/`，仅当该次需要修改路由器时创建。报告返回具体事务号。备份可能含 WiFi 凭据，只限 root，不能上传到仓库。

```bash
# 在机器人上，用报告里的真实事务号替换：
sudo sh /var/backups/robot-network-toolkit/TRANSACTION/rollback.sh
# 在底盘路由器上，仅该事务确实改了它时：
sh /root/robot-network-backups/TRANSACTION/rollback.sh
```

自动化先回滚底盘路由器、再回滚机器人。验收成功会生成 COMMITTED 并取消机器人回滚定时器；底盘路由器看门狗看到 COMMITTED 退出。恢复某次备份会回到**那次变更前**，不等于工厂设置，也不能任意倒退多个事务而忽略相互依赖。

不要执行 `nft flush ruleset`，不要重置路由器、启用所有转发或整段改桥接。当前维护只重载专属表，其他系统防火墙仍需独立核对。

## 发布与复现边界

单元测试只验证参数校验、规则关键保护和状态机逻辑；不能替代 Linux 内核规则加载、真实网卡/路由器/浏览器验收。现场已验证配置持久化保存和服务启用，但没有整机断电重启验收；更换硬件或固件也需重新验收。
