"""Validation, deterministic rendering, and the independently testable failover policy."""
import ipaddress
import re
import shlex


def bound_dns(iface,domain,servers):
    """Resolve A records over the tested NIC, independently of the main route."""
    import os,socket,struct
    def skip(data,offset):
        for _ in range(128):
            size=data[offset]
            if size&0xc0==0xc0:return offset+2
            offset+=1
            if not size:return offset
            offset+=size
        raise ValueError('Invalid DNS name')
    tid=os.urandom(2)
    name=b''.join(bytes([len(x)])+x.encode() for x in domain.split('.'))+b'\0'
    query=tid+struct.pack('!HHHHH',0x100,1,0,0,0)+name+struct.pack('!HH',1,1)
    for server in servers:
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,iface.encode()+b'\0')
                sock.settimeout(1);sock.connect((server,53));sock.send(query);data=sock.recv(4096)
            if data[:2]!=tid:continue
            flags,qd,an,_,_=struct.unpack('!HHHHH',data[2:12])
            if not flags&0x8000 or flags&0x020f:continue
            off=12
            for _ in range(qd):off=skip(data,off)+4
            for _ in range(an):
                off=skip(data,off);typ,cls,ttl,size=struct.unpack('!HHIH',data[off:off+10]);off+=10
                if typ==1 and cls==1 and size==4:return socket.inet_ntoa(data[off:off+4])
                off+=size
        except (OSError,ValueError,IndexError,struct.error):continue
    return None


def validate(config):
    if config['policy']['preferred'] not in ('wifi', 'cellular'):
        raise ValueError('preferred must be wifi or cellular')
    names = [v for v in config['interfaces'].values() if v]
    if len(names) != len(set(names)):
        raise ValueError('Network interface names must be distinct')
    for name in names:
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', name):
            raise ValueError('Invalid interface name')
    net = config['network']
    debug = ipaddress.ip_network(net['debug_cidr'])
    chassis = ipaddress.ip_network(net['chassis_cidr'])
    cell_address = ipaddress.ip_interface(net['cellular_address'])
    chassis_address = ipaddress.ip_interface(net['chassis_address'])
    if debug.version != 4 or chassis.version != 4 or debug.overlaps(chassis):
        raise ValueError('Debug and chassis networks must be disjoint IPv4 networks')
    if cell_address.network != debug or chassis_address.network != chassis:
        raise ValueError('Interface addresses must use their respective subnet')
    if ipaddress.ip_address(net['cellular_gateway']) not in debug:
        raise ValueError('Cellular gateway must be in the debug subnet')
    if ipaddress.ip_address(net['chassis_controller']) not in chassis:
        raise ValueError('Chassis controller must be in the chassis subnet')
    if ipaddress.ip_address(config['chassis_router']['host']) not in chassis:
        raise ValueError('Chassis router must be in the chassis subnet')
    if chassis_address.ip in [ipaddress.ip_address(net['chassis_controller']),
                              ipaddress.ip_address(config['chassis_router']['host'])]:
        raise ValueError('Chassis gateway address conflicts with a device')
    for addr in net['dns']:
        if ipaddress.ip_address(addr).version != 4:
            raise ValueError('DNS addresses must be IPv4')
    for domain in config['policy']['health_domains']:
        if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', domain):
            raise ValueError('Health probes require plain DNS hostnames')
    for key in ['wifi_metric', 'cellular_metric', 'secondary_metric']:
        if not 1 <= config['policy'][key] <= 32000:
            raise ValueError('Invalid route metric')
    p = config['policy']
    if not p['wifi_metric'] < p['cellular_metric'] < p['secondary_metric']:
        raise ValueError('Metrics must order Wi-Fi, cellular, and secondary Wi-Fi')
    for key in ['health_interval_seconds','failures_before_switch','recoveries_before_return','return_hold_seconds']:
        if not isinstance(p[key],int) or p[key] < 1:
            raise ValueError('Invalid health policy value')
    return config


def render_nft(c):
    i, n = c['interfaces'], c['network']
    uplinks = ', '.join('"'+x+'"' for x in
                       [i['cellular'], i['wifi'], i.get('secondary_wifi')] if x)
    return f'''table ip robot_chassis_access {{
 chain forward {{
  type filter hook forward priority filter; policy drop;
  iifname "{i['chassis']}" oifname {{ {uplinks} }} ip saddr {n['chassis_cidr']} ct state new,established,related counter accept
  iifname {{ {uplinks} }} oifname "{i['chassis']}" ip daddr {n['chassis_cidr']} ct state established,related counter accept
  iifname "{i['cellular']}" oifname "{i['chassis']}" ip saddr {n['debug_cidr']} ip daddr {n['chassis_cidr']} ct state new,established,related counter accept
  iifname "{i['chassis']}" oifname "{i['cellular']}" ip saddr {n['chassis_cidr']} ip daddr {n['debug_cidr']} ct state established,related counter accept
 }}
 chain postrouting {{
  type nat hook postrouting priority srcnat; policy accept;
  iifname "{i['chassis']}" oifname {{ {uplinks} }} ip saddr {n['chassis_cidr']} ct direction original counter masquerade
  iifname "{i['cellular']}" oifname "{i['chassis']}" ip saddr {n['debug_cidr']} ip daddr {n['chassis_cidr']} counter masquerade
 }}
}}
'''


def render_return_nft(c):
    i,n=c['interfaces'],c['network']
    return f'''table ip robot_chassis_return_path {{
 set gateway_macs {{ type ether_addr; }}
 chain prerouting {{
  type filter hook prerouting priority -90; policy accept;
  iifname "{i['cellular']}" ether saddr @gateway_macs ip saddr {n['debug_cidr']} ip daddr {n['chassis_cidr']} ct direction original ct mark set (ct mark & 0x00ffffff) | 0x66000000 counter
  iifname "{i['chassis']}" ip saddr {n['chassis_cidr']} ip daddr {n['debug_cidr']} ct direction reply ct mark & 0xff000000 == 0x66000000 meta mark set (meta mark & 0x00ffffff) | 0x66000000 counter
 }}
}}
'''


def router_script(config, action, transaction):
    if not re.fullmatch(r'[A-Za-z0-9_-]+', transaction):
        raise ValueError('Invalid transaction identifier')
    base='/root/robot-network-backups/'+transaction
    q=shlex.quote
    if action == 'confirm':
        return 'touch '+q(base+'/COMMITTED')+'\n'
    if action == 'rollback':
        return 'sh '+q(base+'/rollback.sh')+'\n'
    if action != 'apply':
        raise ValueError('Invalid router action')
    gateway=str(ipaddress.ip_interface(config['network']['chassis_address']).ip)
    dns='\n'.join('uci add_list network.lan.dns='+q(x) for x in config['network']['dns'])
    return f'''set -eu
BASE={q(base)}
[ ! -e "$BASE" ] || exit 2
[ -z "$(uci changes)" ] || {{ echo 'Unsaved UCI changes'; exit 2; }}
umask 077
mkdir -p "$BASE"
cp -p /etc/config/network "$BASE/network.before"
cp -p /etc/config/wireless "$BASE/wireless.before"
ip -4 route show default > "$BASE/default-route.before"
cat > "$BASE/rollback.sh" <<'ROLLBACK'
#!/bin/sh
set -eu
BASE={q(base)}
cp -p "$BASE/network.before" /etc/config/network
cp -p "$BASE/wireless.before" /etc/config/wireless
uci revert network
uci revert wireless
ip -4 route del default dev br-lan 2>/dev/null || true
while IFS= read -r route; do
 [ -z "$route" ] || ip -4 route replace $route
done < "$BASE/default-route.before"
/etc/init.d/dnsmasq reload
wifi reload
ROLLBACK
chmod 700 "$BASE/rollback.sh"
cat > "$BASE/watchdog.sh" <<'WATCHDOG'
#!/bin/sh
trap '' HUP
BASE={q(base)}
i=0
while [ "$i" -lt 144 ]; do
 [ ! -e "$BASE/COMMITTED" ] || exit 0
 sleep 5
 i=$((i+1))
done
exec "$BASE/rollback.sh"
WATCHDOG
sh "$BASE/watchdog.sh" </dev/null >"$BASE/watchdog.log" 2>&1 &
uci set network.lan.gateway={q(gateway)}
uci -q delete network.lan.dns || true
{dns}
uci set wireless.radio0.disabled='1'
uci set wireless.radio1.disabled='1'
uci commit network
uci commit wireless
ip -4 route replace default via {q(gateway)} dev br-lan
/etc/init.d/dnsmasq reload
wifi reload
ip -4 route
'''


def decide(previous, wifi_ok, cellular_ok, now, policy):
    """No network I/O. A dead active link can override the recovery hold period."""
    state=dict(previous)
    state.setdefault('active',policy.get('preferred','wifi'))
    state.setdefault('changed_at',now)
    for name, ok in [('wifi',wifi_ok),('cellular',cellular_ok)]:
        state[name+'_ok']=state.get(name+'_ok',0)+1 if ok else 0
        state[name+'_fail']=0 if ok else state.get(name+'_fail',0)+1
    target=state['active']
    other='cellular' if target=='wifi' else 'wifi'
    healthy={'wifi':wifi_ok,'cellular':cellular_ok}
    preferred=policy.get('preferred','wifi')
    if state[target+'_fail']>=policy['failures_before_switch'] and healthy[other]:
        target=other
    elif target!=preferred and healthy[preferred]:
        recovered=(state[preferred+'_ok']>=policy['recoveries_before_return'] and
                   now-state['changed_at']>=policy['return_hold_seconds'])
        if recovered:target=preferred
    if target!=state['active']:
        state['active']=target;state['changed_at']=now
    state['degraded']=not wifi_ok and not cellular_ok
    return state
