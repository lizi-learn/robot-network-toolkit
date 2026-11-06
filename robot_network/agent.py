#!/usr/bin/env python3
"""Privileged robot-side agent. Never authenticates to routers or stores passwords."""
import argparse
import configparser
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid as uuid_module
from common import validate,render_nft,render_return_nft

ROOT=Path(__file__).resolve().parent.parent
BACKUPS=Path('/var/backups/robot-network-toolkit')
UNITS=['robot-chassis-access.service','robot-chassis-return-path.service',
       'robot-chassis-return-path.timer','robot-network-health.timer']


def run(args,check=True,timeout=30):
    p=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
    if check and p.returncode:
        raise RuntimeError('Command failed: '+repr(args)+'; '+p.stderr.strip()[:300])
    return p


def uuid_for(iface):
    u=run(['nmcli','-g','GENERAL.CON-UUID','dev','show',iface]).stdout.strip()
    if not u or u=='--':raise ValueError('No active NM profile for '+iface)
    return u


def desired(config):
    i,n,p=config['interfaces'],config['network'],config['policy']
    cell_metric=p['cellular_metric'] if p['preferred']=='wifi' else p['wifi_metric']
    wifi_metric=p['wifi_metric'] if p['preferred']=='wifi' else p['cellular_metric']+300
    result={
      i['cellular']:{'ipv4.method':'manual','ipv4.addresses':n['cellular_address'],
                     'ipv4.gateway':n['cellular_gateway'],'ipv4.dns':n['cellular_gateway'],
                     'ipv4.never-default':'no','ipv4.route-metric':str(cell_metric)},
      i['chassis']:{'ipv4.method':'manual','ipv4.addresses':n['chassis_address'],
                    'ipv4.gateway':'','ipv4.dns':'','ipv4.ignore-auto-dns':'yes',
                    'ipv4.never-default':'yes','ipv4.route-metric':'101'},
      i['wifi']:{'ipv4.route-metric':str(wifi_metric),'ipv4.never-default':'no'}}
    if i.get('secondary_wifi'):
        result[i['secondary_wifi']]={'ipv4.route-metric':str(p['secondary_metric'])}
    return result


def changes(config):
    result=[]
    for iface, settings in desired(config).items():
        try:u=uuid_for(iface)
        except ValueError:
            if iface==config['interfaces'].get('secondary_wifi'):continue
            raise
        updates={}
        for prop,wanted in settings.items():
            current=run(['nmcli','-g',prop,'con','show',u]).stdout.strip()
            if current!=wanted:updates[prop]={'from':current,'to':wanted}
        result.append({'interface':iface,'uuid':u,'changes':updates})
    return result


def audit(config):
    return {'addresses':json.loads(run(['ip','-j','-4','addr']).stdout),
            'routes':json.loads(run(['ip','-j','-4','route']).stdout),
            'changes':changes(config),
            'services':{u:run(['systemctl','is-active',u],False).stdout.strip() for u in UNITS}}


def units_ready():
    for unit in UNITS:
        expected='static' if unit=='robot-chassis-return-path.timer' else 'enabled'
        if run(['systemctl','is-enabled',unit],False).stdout.strip()!=expected:return False
        if run(['systemctl','is-active',unit],False).stdout.strip()!='active':return False
    return True


def probe_address(iface,address):
    """RFC 5227 style LAN-only duplicate-address probes, before assigning an IP."""
    import socket,struct,time
    target=socket.inet_aton(address)
    mac=bytes.fromhex(Path('/sys/class/net/'+iface+'/address').read_text().strip().replace(':',''))
    packet=b'\xff'*6+mac+b'\x08\x06'+struct.pack('!HHBBH6s4s6s4s',1,0x0800,6,4,1,mac,b'\0'*4,b'\0'*6,target)
    conflicts=set()
    with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0806)) as sock:
        sock.bind((iface,0));sock.settimeout(.2)
        for _ in range(3):
            sock.send(packet);end=time.monotonic()+1.1
            while time.monotonic()<end:
                try:data=sock.recv(2048)
                except socket.timeout:continue
                if len(data)<42 or data[12:14]!=b'\x08\x06':continue
                if data[22:28]!=mac and (data[28:32]==target or (data[28:32]==b'\0'*4 and data[38:42]==target)):
                    conflicts.add(data[22:28].hex(':'))
    if conflicts:raise ValueError('Address conflict for '+address+': '+','.join(sorted(conflicts)))


def assets(config):
    cell=config['interfaces']['cellular']
    result={
      '/etc/robot-network/site.json':json.dumps(config,indent=2)+'\n',
      '/etc/nftables.d/robot-chassis-access.nft':render_nft(config),
      '/etc/nftables.d/robot-chassis-return-path.nft':render_return_nft(config),
      '/usr/local/sbin/robot-chassis-access':(ROOT/'assets/robot-chassis-access').read_text(),
      '/usr/local/sbin/robot-chassis-return-path':(ROOT/'assets/robot-chassis-return-path').read_text(),
      '/usr/local/lib/robot-network/common.py':(ROOT/'robot_network/common.py').read_text(),
      '/usr/local/lib/robot-network/health.py':(ROOT/'robot_network/health.py').read_text(),
    }
    # Only non-secret, robot-side settings are written to the controller.
    slim={k:config[k] for k in ['interfaces','network','policy']}
    result['/etc/robot-network/site.json']=json.dumps(slim,indent=2)+'\n'
    for name in ['robot-chassis-access.service','robot-chassis-return-path.service',
                 'robot-chassis-return-path.timer','robot-chassis-return-path-sync.service',
                 'robot-network-health.service','robot-network-health.timer']:
        result['/etc/systemd/system/'+name]=(ROOT/'assets'/name).read_text()
    timer='/etc/systemd/system/robot-network-health.timer'
    result[timer]=result[timer].replace('OnUnitActiveSec=10s','OnUnitActiveSec='+str(config['policy']['health_interval_seconds'])+'s')
    result['/etc/systemd/system/robot-chassis-access.service.d/return-path.conf']=(ROOT/'assets/return-path.conf').read_text()
    dispatcher=(ROOT/'assets/90-robot-chassis-return-path').read_text()
    # This dispatcher invokes a runtime configuration lookup instead of a fixed NIC.
    result['/etc/NetworkManager/dispatcher.d/90-robot-chassis-return-path']=dispatcher
    return result


def snapshot(config, transaction, files):
    base=BACKUPS/transaction
    base.mkdir(parents=True,mode=0o700,exist_ok=False)
    os.chmod(base,0o700)
    manifest={'files':{},'profiles':{},'units':{},'transaction':transaction,
              'ip_forward':Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()}
    for path in files:
        src=Path(path);name=hashlib.sha256(path.encode()).hexdigest()
        entry={'exists':src.exists(),'backup':name}
        if src.exists():
            shutil.copy2(src,base/name);entry['mode']=src.stat().st_mode&0o777
        manifest['files'][path]=entry
    import gi
    gi.require_version('NM','1.0')
    from gi.repository import NM
    client=NM.Client.new(None)
    for iface in desired(config):
        dev=client.get_device_by_iface(iface)
        if not dev:continue
        applied,version=dev.get_applied_connection(0,None)
        if not applied:continue
        profile_uuid=applied.get_uuid()
        nmfile=None
        for path in Path('/etc/NetworkManager/system-connections').glob('*'):
            parser=configparser.ConfigParser(interpolation=None,strict=False)
            try:
                parser.read(path)
                if parser.get('connection','uuid',fallback='')==profile_uuid:nmfile=path;break
            except (configparser.Error,UnicodeError):continue
        if not nmfile:raise ValueError('Cannot find persisted NM profile '+profile_uuid)
        name='nm-'+profile_uuid
        shutil.copy2(nmfile,base/name)
        applied_name='applied-'+profile_uuid
        (base/applied_name).write_text(applied.to_dbus(NM.ConnectionSerializationFlags.ALL).print_(True))
        manifest['profiles'][iface]={'file':str(nmfile),'backup':name,'applied':applied_name}
    for unit in UNITS:
        manifest['units'][unit]={'enabled':run(['systemctl','is-enabled',unit],False).stdout.strip(),
                                 'active':run(['systemctl','is-active',unit],False).stdout.strip()}
    (base/'manifest.json').write_text(json.dumps(manifest,indent=2))
    shutil.copy2(__file__,base/'agent.py')
    shutil.copy2(Path(__file__).with_name('common.py'),base/'common.py')
    rollback=f'#!/bin/sh\nexec /usr/bin/python3 {base}/agent.py rollback --backup {base}\n'
    (base/'rollback.sh').write_text(rollback);os.chmod(base/'rollback.sh',0o700)
    (base/'guard.sh').write_text('#!/bin/sh\n[ ! -e '+str(base)+'/COMMITTED ] || exit 0\nexec /bin/sh '+str(base)+'/rollback.sh\n')
    run(['systemd-run','--unit=robot-network-rollback-'+transaction,'--on-active=12m',
         '/bin/sh',str(base/'guard.sh')])
    return base


def rollback(base):
    base=Path(base);manifest=json.loads((base/'manifest.json').read_text())
    run(['systemctl','stop','robot-network-health.timer','robot-network-health.service'],False)
    run(['systemctl','stop','robot-chassis-return-path.timer','robot-chassis-return-path.service'],False)
    for path,entry in manifest['files'].items():
        dest=Path(path)
        if entry['exists']:
            dest.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(base/entry['backup'],dest)
        else:dest.unlink(missing_ok=True)
    for iface,entry in manifest['profiles'].items():shutil.copy2(base/entry['backup'],entry['file'])
    run(['nmcli','connection','reload'])
    import gi
    gi.require_version('NM','1.0')
    from gi.repository import NM,GLib
    client=NM.Client.new(None)
    for iface,entry in manifest['profiles'].items():
        variant=GLib.Variant.parse(GLib.VariantType('a{sa{sv}}'),(base/entry['applied']).read_text(),None,None)
        connection=NM.SimpleConnection.new_from_dbus(variant)
        device=client.get_device_by_iface(iface)
        if device:device.reapply(connection,0,0,None)
    run(['systemctl','daemon-reload'])
    for unit,status in manifest['units'].items():
        run(['systemctl','enable' if status['enabled']=='enabled' else 'disable',unit],False)
    # Restore only the tables and services owned by this toolkit.
    loader=Path('/usr/local/sbin/robot-chassis-access')
    if loader.exists():run([str(loader),'reload'])
    elif not manifest['files']['/etc/nftables.d/robot-chassis-access.nft']['exists']:
        run(['nft','delete','table','ip','robot_chassis_access'],False)
    if not manifest['files']['/etc/nftables.d/robot-chassis-return-path.nft']['exists']:
        run(['nft','delete','table','ip','robot_chassis_return_path'],False)
    for unit,status in manifest['units'].items():
        run(['systemctl','restart' if status['active']=='active' else 'stop',unit],False)
    run(['sysctl','-q','-w','net.ipv4.ip_forward='+manifest['ip_forward']])
    (base/'ROLLED_BACK').write_text('yes\n')
    return {'rolled_back':str(base)}


def apply(config,transaction):
    plan=changes(config);files=assets(config)
    different=[p for p,v in files.items() if not Path(p).exists() or Path(p).read_text()!=v]
    if not different and not any(x['changes'] for x in plan) and units_ready():
        return {'changed':False,'reason':'All desired settings already applied'}
    for label,property_name in [('cellular','cellular_address'),('chassis','chassis_address')]:
        iface=config['interfaces'][label]
        wanted=config['network'][property_name].split('/')[0]
        rows=json.loads(run(['ip','-j','-4','address','show','dev',iface]).stdout)
        if not any(a.get('local')==wanted for row in rows for a in row.get('addr_info',[])):
            probe_address(iface,wanted)
    # Refuse to take over a policy-rule priority that belongs to something else.
    rules=json.loads(run(['ip','-j','-4','rule']).stdout)
    for rule in rules:
        if rule.get('priority')==16600 and str(rule.get('table'))!='16600':
            raise ValueError('Policy-rule priority 16600 is occupied')
    base=snapshot(config,transaction,files)
    try:
        run(['systemctl','stop','robot-network-health.timer','robot-network-health.service'],False)
        for path,text in files.items():
            dest=Path(path);dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_text(text)
            executable=('/sbin/' in path or '/dispatcher.d/' in path)
            os.chmod(dest,0o755 if executable else 0o644)
        # The loader validates the complete atomic batch before modifying nftables.
        run(['/usr/local/sbin/robot-chassis-access','reload'])
        for item in plan:
            if not item['changes']:continue
            args=['nmcli','con','modify','uuid',item['uuid']]
            for prop,value in item['changes'].items():args.extend([prop,value['to']])
            run(args)
            result=run(['nmcli','device','reapply',item['interface']],False)
            if result.returncode:
                raise RuntimeError('NM cannot reapply '+item['interface']+'; automatic rollback will restore it')
        run(['systemctl','daemon-reload'])
        run(['systemctl','enable',*UNITS])
        run(['systemctl','restart','robot-chassis-access.service'])
        run(['systemctl','start','robot-chassis-return-path.service','robot-chassis-return-path.timer'])
        run(['systemctl','enable','--now','robot-network-health.timer'])
        return {'changed':True,'backup':str(base),'transaction':transaction,'changed_files':different,'network_changes':plan}
    except Exception:
        rollback(base)
        run(['systemctl','stop','robot-network-rollback-'+transaction+'.timer'],False)
        raise


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser()
    parser.add_argument('action',choices=['audit','apply','confirm','rollback','force'])
    parser.add_argument('--request');parser.add_argument('--backup');parser.add_argument('--mode',choices=['wifi','cellular'])
    args=parser.parse_args()
    if os.geteuid()!=0:raise SystemExit('Robot-side agent requires root')
    with open('/run/robot-network-toolkit.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if args.action=='rollback':result=rollback(args.backup)
        else:
            data=json.loads(Path(args.request).read_text());config=validate(data['config'])
            transaction=data['transaction']
            if not transaction.replace('-','').isalnum():raise ValueError('Invalid transaction')
            if args.action=='audit':result=audit(config)
            elif args.action=='apply':result=apply(config,transaction)
            elif args.action=='force':
                run(['/usr/bin/python3','/usr/local/lib/robot-network/health.py',args.mode])
                result={'forced':args.mode}
            else:
                base=BACKUPS/transaction
                (base/'COMMITTED').write_text('yes\n')
                run(['systemctl','stop','robot-network-rollback-'+transaction+'.timer'],False)
                result={'committed':transaction}
        print(json.dumps(result,ensure_ascii=False))

if __name__=='__main__':main()
