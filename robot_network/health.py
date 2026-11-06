#!/usr/bin/env python3
"""Bound HTTPS reachability checks with failure/recovery hysteresis (IPv4 only)."""
import concurrent.futures
import fcntl
import json
from pathlib import Path
import subprocess
import sys
import time
from common import decide,bound_dns

CONFIG=Path('/etc/robot-network/site.json')
STATE=Path('/run/robot-network-health.json')


def run(args,check=True):
    return subprocess.run(args,text=True,capture_output=True,check=check,timeout=15)


def metrics(config, active):
    p=config['policy'];i=config['interfaces']
    if active=='wifi':
        return {i['wifi']:p['wifi_metric'],i['cellular']:p['cellular_metric']}
    return {i['wifi']:p['cellular_metric']+300,i['cellular']:p['wifi_metric']}


def set_active(config,active):
    changes=[]
    for iface, metric in metrics(config,active).items():
        uuid=run(['nmcli','-g','GENERAL.CON-UUID','dev','show',iface]).stdout.strip()
        if not uuid or uuid=='--':
            continue
        old=run(['nmcli','-g','ipv4.route-metric','con','show',uuid]).stdout.strip()
        if old==str(metric):
            continue
        run(['nmcli','con','modify','uuid',uuid,'ipv4.route-metric',str(metric)])
        run(['nmcli','device','reapply',iface])
        changes.append({'interface':iface,'metric':metric})
    return changes


def probe(iface,domain,servers):
    ip=bound_dns(iface,domain,servers)
    if not ip:return False
    p=run(['curl','--noproxy','*','-4','--interface',iface,'--head',
           '--resolve',domain+':443:'+ip,
           '--connect-timeout','1.5','--max-time','2.5','-sS','-o','/dev/null',
           '-w','%{http_code}','https://'+domain+'/'],check=False)
    # An authenticated business call is deliberately unnecessary. A 404 at /
    # still proves a verified TLS session and an HTTP response from the platform.
    return p.returncode==0 and p.stdout.strip().isdigit() and int(p.stdout)>0


def main():
    with open('/run/robot-network-health.lock','w') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return
        config=json.loads(CONFIG.read_text());now=time.time()
        previous=json.loads(STATE.read_text()) if STATE.exists() else {}
        force=sys.argv[1] if len(sys.argv)>1 else None
        if force in ['wifi','cellular']:
            state=dict(previous,active=force,changed_at=now)
            changes=set_active(config,force)
        else:
            jobs={}
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                for link in ['wifi','cellular']:
                    iface=config['interfaces'][link]
                    jobs[link]=[pool.submit(probe,iface,d,config['network']['dns']) for d in config['policy']['health_domains']]
                status={k:any(f.result() for f in fs) for k,fs in jobs.items()}
            state=decide(previous,status['wifi'],status['cellular'],now,config['policy'])
            state['last_probe']=status
            changes=set_active(config,state['active'])
        STATE.write_text(json.dumps(state,indent=2)+'\n')
        if changes or state.get('degraded'):
            print(json.dumps({'active':state['active'],'changes':changes,
                              'degraded':state.get('degraded',False)}),flush=True)

if __name__=='__main__':main()
