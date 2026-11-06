#!/usr/bin/env python3
"""Local operator CLI. Credentials stay in memory; reports are local and ignored by Git."""
import argparse
import base64
import datetime
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shlex
import socket
import sys
import time
import uuid
import paramiko
from common import validate,router_script
from chassis_status import read_status

ROOT=Path(__file__).resolve().parent.parent


def fingerprint(key):
    return 'SHA256:'+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


class PinnedHost(paramiko.MissingHostKeyPolicy):
    def __init__(self,expected):self.expected=expected
    def missing_host_key(self,client,hostname,key):
        if fingerprint(key)!=self.expected:
            raise paramiko.SSHException('SSH fingerprint mismatch for '+hostname+'; observed '+fingerprint(key))
        client.get_host_keys().add(hostname,key.get_name(),key)


def secret(name,label,default=None):
    if os.environ.get(name):return os.environ[name]
    if default is not None:return default
    return getpass.getpass(label+': ')


def connect_robot(config,password,client=False):
    r=config['test_client'] if client else config['robot']
    hosts=r.get('hosts',[r.get('host')]);errors=[]
    if not str(r['host_key_sha256']).startswith('SHA256:'):
        raise ValueError('Set the verified SHA256 host key fingerprint in the private site config first')
    for host in hosts:
        if not host:continue
        c=paramiko.SSHClient();c.set_missing_host_key_policy(PinnedHost(r['host_key_sha256']))
        sock=None
        try:
            if r.get('source_ip'):
                sock=socket.create_connection((host,r.get('port',22)),5,source_address=(r['source_ip'],0))
            disabled=None
            if r.get('host_key_type'):
                disabled={'keys':[k for k in paramiko.Transport._preferred_keys if k!=r['host_key_type']]}
            c.connect(host,port=r.get('port',22),username=r['username'],password=password,
                      key_filename=r.get('key_filename'),allow_agent=False,look_for_keys=False,
                      timeout=5,banner_timeout=5,auth_timeout=5,sock=sock,disabled_algorithms=disabled)
            c.get_transport().set_keepalive(10);return c
        except (OSError,paramiko.SSHException) as e:
            errors.append(host+': '+type(e).__name__+' '+str(e));c.close()
    raise ConnectionError('; '.join(errors))


def connect_router(robot,config,password):
    r=config['chassis_router']
    channel=robot.get_transport().open_channel('direct-tcpip',(r['host'],22),('127.0.0.1',0))
    t=paramiko.Transport(channel);t.start_client(timeout=8)
    if fingerprint(t.get_remote_server_key())!=r['host_key_sha256']:
        t.close();raise paramiko.SSHException('Chassis router SSH fingerprint mismatch')
    t.auth_password(r.get('username','root'),password);return t


def exec_robot(robot,cmd,sudo_password=None,data=None,timeout=90):
    if sudo_password is not None:cmd='sudo -S -p '+shlex.quote('')+' '+cmd
    i,o,e=robot.exec_command(cmd,timeout=timeout)
    if sudo_password is not None:i.write(sudo_password+'\n')
    if data is not None:i.write(json.dumps(data))
    i.flush();i.channel.shutdown_write()
    out=o.read().decode(errors='replace');err=e.read().decode(errors='replace');rc=o.channel.recv_exit_status()
    if rc:raise RuntimeError('Remote command failed: '+err[:300]+' '+out[:300])
    return out


def exec_router(transport,text):
    ch=transport.open_session();ch.settimeout(45);ch.exec_command(text)
    out=ch.makefile().read().decode(errors='replace');err=ch.makefile_stderr().read().decode(errors='replace')
    rc=ch.recv_exit_status()
    if rc:raise RuntimeError('Chassis router command failed: '+err[:200]+' '+out[:200])
    return out


def upload(robot,config,transaction):
    dest='/tmp/robot-network-toolkit-'+transaction
    s=robot.open_sftp();s.mkdir(dest,0o700)
    for folder in ['robot_network','assets']:
        s.mkdir(dest+'/'+folder,0o700)
        for path in (ROOT/folder).iterdir():
            if path.is_file() and path.suffix!='.pyc':s.put(str(path),dest+'/'+folder+'/'+path.name)
    req=dest+'/request.json'
    with s.open(req,'w') as f:f.write(json.dumps({'config':config,'transaction':transaction}))
    s.chmod(req,0o600);s.close();return dest,req


def router_audit(t):
    script='''lua - <<'LUA'
local keys={'network.lan.gateway','network.lan.dns','wireless.radio0.disabled','wireless.radio1.disabled'}
for _,k in ipairs(keys) do
 local f=io.popen('uci -q get '..k);local v=f:read('*a') or '';f:close();print(k..'='..v:gsub('\\n',' '))
end
LUA'''
    data={}
    for line in exec_router(t,script).splitlines():
        if '=' in line:k,v=line.split('=',1);data[k]=v.strip()
    return data


def router_matches(c,data):
    ip=str(ipaddress.ip_interface(c['network']['chassis_address']).ip)
    return (data.get('network.lan.gateway')==ip and
            set(data.get('network.lan.dns','').split())==set(c['network']['dns']) and
            data.get('wireless.radio0.disabled')=='1' and data.get('wireless.radio1.disabled')=='1')


def fiveg_guard(robot,c,dest,password):
    mac=exec_robot(robot,'cat /sys/class/net/'+shlex.quote(c['interfaces']['cellular'])+'/address').strip()
    request={'config':c,'password':password,'cellular_mac':mac}
    data=json.loads(exec_robot(robot,'python3 '+shlex.quote(dest+'/robot_network/router_web.py'),data=request))
    return data


def tests(robot,router,c,dest,req,sudo_password,samples,client_password,timer_active=True):
    data=json.loads(exec_robot(robot,'python3 '+shlex.quote(dest+'/robot_network/check.py')+' --request '+shlex.quote(req)+' --samples '+str(samples),sudo_password))
    data['chassis_diagnosis']=read_status(robot,c['network']['chassis_controller'],c['network']['chassis_ws_port'])
    data['chassis_router']=router_audit(router)
    data['client_http']=None
    if c.get('test_client'):
        client=connect_robot(c,client_password,True)
        try:
            dev=c['test_client'].get('interface','wlan0')
            url=f"http://{c['network']['chassis_controller']}:{c['network']['chassis_http_port']}/"
            cmd='curl --noproxy '+shlex.quote('*')+' --interface '+shlex.quote(dev)+' --max-time 8 -sS -o /dev/null -w '+shlex.quote('%{http_code}')+' '+shlex.quote(url)
            data['client_http']=[exec_robot(client,cmd).strip() for _ in range(5)]
        finally:client.close()
    routes=data['ipv4_routes'];chassis_if=c['interfaces']['chassis']
    no_loop=not any(r.get('dst')=='default' and r.get('dev')==chassis_if for r in routes)
    dx=data['chassis_diagnosis']['diagnosis']
    data['checks']={
      'chassis_http_200':data['chassis_http']['stdout']=='200',
      'chassis_internet_latest':bool(dx.get('internet',{}).get('status')),
      'chassis_dns_latest':all(v.get('status') for k,v in dx.items() if k.startswith('DNS')),
      'chassis_gateway_preserved':data['chassis_diagnosis']['ethernet']['gateway']==c['chassis_router']['host'],
      'chassis_router_wired':router_matches(c,data['chassis_router']),
      'no_default_via_chassis':no_loop,
      'managed_services_active':all(v=='active' for u,v in data['services'].items() if timer_active or u!='robot-network-health.timer'),
      'both_uplinks_respond':all(p.get('success',0)==p.get('count') and p.get('count',0)>0 for p in data['probes']),
    }
    if data['client_http'] is not None:data['checks']['client_http_200']=data['client_http']==['200']*5
    data['passed']=all(data['checks'].values())
    return data


def main():
    p=argparse.ArgumentParser(description='Robot network configuration and read-only validation')
    p.add_argument('command',choices=['optimize','test','benchmark'])
    p.add_argument('--config',required=True);p.add_argument('--apply',action='store_true')
    p.add_argument('--samples',type=int,default=5);p.add_argument('--skip-fiveg',action='store_true')
    p.add_argument('--exercise-failover',action='store_true',help='Explicitly switch IPv4 egress to 5G then Wi-Fi and restore; may interrupt calls')
    p.add_argument('--windows',type=int,default=3);p.add_argument('--pause',type=int,default=30)
    p.add_argument('--report-dir',default='reports');args=p.parse_args()
    if args.exercise_failover and args.command!='test':p.error('--exercise-failover is only for test')
    c=validate(json.loads(Path(args.config).read_text()))
    def reject_secrets(value):
        if isinstance(value,dict):
            for key,val in value.items():
                if any(x in key.lower() for x in ['password','token','private_key_data']):
                    raise ValueError('Credentials must not be stored in the site JSON')
                reject_secrets(val)
        elif isinstance(value,list):
            for val in value:reject_secrets(val)
    reject_secrets(c)
    robot_pw=secret('ROBOT_SSH_PASSWORD','Robot SSH password (empty for SSH key)')
    sudo_pw=secret('ROBOT_SUDO_PASSWORD','Robot sudo password',robot_pw if robot_pw else None)
    router_pw=secret('CHASSIS_SSH_PASSWORD','Chassis router SSH password')
    fiveg_pw=None if args.skip_fiveg else secret('FIVEG_PASSWORD','5G router admin password')
    client_pw=secret('CLIENT_SSH_PASSWORD','Test client SSH password') if c.get('test_client') else None
    transaction=datetime.datetime.now().strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:6]
    report_dir=Path(args.report_dir);report_dir.mkdir(parents=True,exist_ok=True)
    os.chmod(report_dir,0o700)
    robot=connect_robot(c,robot_pw);router=None;robot_applied=False;router_applied=False
    result={'transaction':transaction,'mode':args.command,'apply':args.apply}
    try:
        router=connect_router(robot,c,router_pw)
        dest,req=upload(robot,c,transaction)
        agent='python3 '+shlex.quote(dest+'/robot_network/agent.py')
        request_arg=' --request '+shlex.quote(req)
        result['before']=json.loads(exec_robot(robot,agent+' audit'+request_arg,sudo_pw))
        result['router_before']=router_audit(router)
        if not args.skip_fiveg:
            result['fiveg']=fiveg_guard(robot,c,dest,fiveg_pw)
            if not result['fiveg']['route_ok'] or not result['fiveg']['reservation_ok']:
                raise RuntimeError('Configure the documented 5G LAN route/reservation before applying; no device changed')
        if args.command=='benchmark':
            output=dest+'/benchmark.jsonl'
            result['benchmark_log']=exec_robot(robot,'python3 '+shlex.quote(dest+'/robot_network/benchmark.py')+request_arg+' --output '+shlex.quote(output)+' --windows '+str(args.windows)+' --pause '+str(args.pause),sudo_pw,timeout=1200)
            local=report_dir/(transaction+'-samples.jsonl')
            # The root probe intentionally creates a 0600 file; transfer through
            # the existing sudo channel rather than loosening its permissions.
            local.write_text(exec_robot(robot,'cat '+shlex.quote(output),sudo_pw,timeout=30));os.chmod(local,0o600)
            result['samples_file']=str(local)
        elif args.command=='optimize' and args.apply:
            result['optimization']=json.loads(exec_robot(robot,agent+' apply'+request_arg,sudo_pw))
            robot_applied=result['optimization'].get('changed',False)
            if not router_matches(c,result['router_before']):
                router_applied=True
                exec_router(router,router_script(c,'apply',transaction))
            # Allow background chassis diagnostics and first health sample to refresh.
            time.sleep(12)
            result['tests']=tests(robot,router,c,dest,req,sudo_pw,args.samples,client_pw)
            if not result['tests']['passed']:
                raise RuntimeError('Post-apply validation failed; restoring the transaction')
            if router_applied:exec_router(router,router_script(c,'confirm',transaction))
            if robot_applied:result['commit']=json.loads(exec_robot(robot,agent+' confirm'+request_arg,sudo_pw))
        elif args.command=='test':
            result['tests']=tests(robot,router,c,dest,req,sudo_pw,args.samples,client_pw)
            if args.exercise_failover:
                original=(result['tests'].get('health_state') or {}).get('active',c['policy']['preferred'])
                exercise={}
                exec_robot(robot,'systemctl stop robot-network-health.timer robot-network-health.service',sudo_pw)
                try:
                    for mode in ['cellular','wifi']:
                        exec_robot(robot,agent+' force'+request_arg+' --mode '+mode,sudo_pw)
                        time.sleep(12)
                        sample=tests(robot,router,c,dest,req,sudo_pw,args.samples,client_pw,False)
                        selected=min((r for r in sample['ipv4_routes'] if r.get('dst')=='default'),key=lambda r:r.get('metric',0))
                        sample['checks']['requested_egress_selected']=selected['dev']==c['interfaces'][mode]
                        sample['passed']=all(sample['checks'].values());exercise[mode]=sample
                finally:
                    exec_robot(robot,agent+' force'+request_arg+' --mode '+original,sudo_pw)
                    exec_robot(robot,'systemctl start robot-network-health.timer',sudo_pw)
                result['controlled_switch']=exercise
                result['tests']['passed']=result['tests']['passed'] and all(x['passed'] for x in exercise.values())
        else:result['note']='Dry run only. Add --apply to change settings.'
        path=report_dir/(transaction+'.json');path.write_text(json.dumps(result,ensure_ascii=False,indent=2));os.chmod(path,0o600)
        print(json.dumps({'report':str(path),'transaction':transaction,
                          'changed':result.get('optimization',{}).get('changed',False),
                          'checks':result.get('tests',{}).get('checks'),
                          'note':result.get('note')},ensure_ascii=False,indent=2))
        if result.get('tests',{}).get('passed') is False:raise SystemExit(1)
    except Exception as error:
        result['error']=str(error)
        if router_applied:
            try:result['router_rollback']=exec_router(router,router_script(c,'rollback',transaction))
            except Exception as e:result['router_rollback_error']=type(e).__name__
        if robot_applied:
            try:
                base='/var/backups/robot-network-toolkit/'+transaction
                result['robot_rollback']=json.loads(exec_robot(robot,agent+' rollback --backup '+shlex.quote(base),sudo_pw))
                exec_robot(robot,'systemctl stop '+shlex.quote('robot-network-rollback-'+transaction+'.timer'),sudo_pw)
            except Exception as e:result['robot_rollback_error']=type(e).__name__
        path=report_dir/(transaction+'-failed.json');path.write_text(json.dumps(result,ensure_ascii=False,indent=2));os.chmod(path,0o600)
        print(json.dumps({'error':str(error),'report':str(path)},ensure_ascii=False));raise SystemExit(1)
    finally:
        if router:router.close()
        robot.close()

if __name__=='__main__':main()
