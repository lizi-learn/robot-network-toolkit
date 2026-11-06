#!/usr/bin/env python3
"""Robot-side, interface-bound probes. Does not alter routing or interface state."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import statistics
import subprocess
import time


def run(args):
    p=subprocess.run(args,text=True,capture_output=True,timeout=12)
    return {'rc':p.returncode,'stdout':p.stdout.strip(),'stderr':p.stderr.strip()[:180]}


def quantile(xs,q):
    xs=sorted(xs)
    if not xs:return None
    k=(len(xs)-1)*q;a=int(k);b=min(a+1,len(xs)-1)
    return round(xs[a]+(xs[b]-xs[a])*(k-a),3)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--request',required=True)
    parser.add_argument('--samples',type=int,default=5);args=parser.parse_args()
    if not 1<=args.samples<=60:raise ValueError('Samples must be between 1 and 60')
    config=json.loads(Path(args.request).read_text())['config'];net=config['network'];iface=config['interfaces']
    routes=run(['ip','-j','-4','route'])
    domains=config['policy']['health_domains']
    addresses=json.loads(run(['ip','-j','-4','address'])['stdout'])
    local_ips={x['ifname']:{a['local'] for a in x.get('addr_info',[]) if a.get('family')=='inet'} for x in addresses}
    # Resolve once, so both egress interfaces reach exactly the same endpoint.
    import socket
    endpoints={}
    for d in domains:
        try:endpoints[d]=socket.getaddrinfo(d,443,socket.AF_INET,socket.SOCK_STREAM)[0][4][0]
        except socket.gaierror:endpoints[d]=None
    def probe(link,domain):
        dev=iface[link];ip=endpoints[domain];samples=[]
        if not ip:return {'link':link,'domain':domain,'error':'DNS resolution failed'}
        for n in range(args.samples):
            p=run(['curl','--noproxy','*','-4','--interface',dev,'--resolve',domain+':443:'+ip,
                   '--head','--http1.1','--connect-timeout','2','--max-time','4',
                   '-sS','-o','/dev/null','-w','%{json}','https://'+domain+'/'])
            try:x=json.loads(p['stdout'])
            except ValueError:x={}
            samples.append({'rc':p['rc'],'http':x.get('http_code',0),'local':x.get('local_ip'),
                            'remote':x.get('remote_ip'),'tcp_ms':x.get('time_connect',0)*1000,
                            'tls_ready_ms':x.get('time_appconnect',0)*1000,
                            'first_byte_ms':x.get('time_starttransfer',0)*1000})
            time.sleep(.15)
        good=[s for s in samples if s['rc']==0 and s['http']>0 and s['remote']==ip and s['local'] in local_ips.get(dev,set())]
        return {'link':link,'domain':domain,'pinned_ipv4':ip,'success':len(good),'count':len(samples),
                'tcp_median_ms':quantile([s['tcp_ms'] for s in good],.5),
                'tcp_p95_ms':quantile([s['tcp_ms'] for s in good],.95),
                'tls_median_ms':quantile([s['tls_ready_ms'] for s in good],.5),
                'samples':samples}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures=[pool.submit(probe,link,d) for d in domains for link in ['wifi','cellular']]
        probes=[f.result() for f in futures]
    http=run(['curl','--noproxy','*','-sS','--max-time','5','-o','/dev/null',
              '-w','%{http_code}',f"http://{net['chassis_controller']}:{net['chassis_http_port']}/"])
    state=Path('/run/robot-network-health.json')
    result={'ipv4_routes':json.loads(routes['stdout']),'health_state':json.loads(state.read_text()) if state.exists() else None,
            'chassis_http':http,'probes':probes,
            'services':{u:run(['systemctl','is-active',u])['stdout'] for u in
                        ['robot-chassis-access.service','robot-chassis-return-path.service',
                         'robot-chassis-return-path.timer','robot-network-health.timer']}}
    print(json.dumps(result,ensure_ascii=False))

if __name__=='__main__':main()
