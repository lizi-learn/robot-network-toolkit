#!/usr/bin/env python3
"""Read-only, paired IPv4 benchmark with multiple observation windows.
Raw output contains site network metadata; keep it private.
"""
import argparse
import concurrent.futures as cf
import datetime, ipaddress, json, os, re, socket, struct, subprocess, threading, time
from pathlib import Path
from zoneinfo import ZoneInfo
LOCK=threading.Lock()
CONFIG={}
WINDOW=0
def emit(row):
    row['window']=WINDOW
    row['observed_at']=datetime.datetime.now(ZoneInfo('Asia/Shanghai')).isoformat()
    with LOCK: FH.write(json.dumps(row,ensure_ascii=False)+'\n')

def event(**kw):
    print(json.dumps(kw,ensure_ascii=False),flush=True)

def output(args):return subprocess.check_output(args,text=True,timeout=8).strip()

def skip(data,off):
    for _ in range(128):
        n=data[off]
        if n&0xc0==0xc0:return off+2
        off+=1
        if not n:return off
        off+=n
    raise ValueError('Invalid DNS name')

def dns(iface,domain,n):
    cfg=CONFIG[iface];tid=os.urandom(2)
    qname=b''.join(bytes([len(p)])+p.encode() for p in domain.split('.'))+b'\0'
    q=tid+struct.pack('!HHHHH',0x100,1,0,0,0)+qname+struct.pack('!HH',1,1)
    start=time.monotonic();row={'type':'dns','iface':iface,'domain':domain,'n':n,'server':cfg['dns']}
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,iface.encode()+b'\0')
            s.bind((cfg['ip'],0));s.settimeout(2);s.sendto(q,(cfg['dns'],53));data,_=s.recvfrom(4096)
        assert data[:2]==tid
        flags,qd,an,ns,ar=struct.unpack('!HHHHH',data[2:12]);off=12;answers=[]
        for _ in range(qd):off=skip(data,off)+4
        for _ in range(an):
            off=skip(data,off);typ,cls,ttl,size=struct.unpack('!HHIH',data[off:off+10]);off+=10
            if typ==1 and size==4:answers.append(socket.inet_ntoa(data[off:off+size]))
            off+=size
        row.update(rcode=flags&15,answers=answers,elapsed_ms=(time.monotonic()-start)*1000)
    except Exception as e:row['error']=type(e).__name__
    emit(row);return row

def ping(iface,target,label):
    args=['ping','-4','-n','-I',iface,'-c','120','-i','0.5','-W','1','-w','65',target]
    p=subprocess.run(args,capture_output=True,text=True,timeout=70)
    times=[float(x) for x in re.findall(r'time[=<]([\d.]+) ms',p.stdout)]
    summary=re.search(r'(\d+) packets transmitted, (\d+) received',p.stdout)
    row={'type':'ping','iface':iface,'target':target,'label':label,'rc':p.returncode,
         'sent':int(summary.group(1)) if summary else 120,
         'received':int(summary.group(2)) if summary else len(times),'rtt_ms':times,'stderr':p.stderr.strip()}
    emit(row);event(stage='ping_complete',iface=iface,label=label,received=row['received'],sent=row['sent'])

def https(iface,domain,ip,round_no,count=15):
    for n in range(count):
        args=['curl','--noproxy','*','-4','--interface',iface,'--resolve',domain+':443:'+ip,
              '--http1.1','--head','--connect-timeout','2','--max-time','4','-sS',
              '-o','/dev/null','-w','%{json}','https://'+domain+'/']
        p=subprocess.run(args,capture_output=True,text=True,timeout=6)
        try:x=json.loads(p.stdout)
        except ValueError:x={}
        row={'type':'https','iface':iface,'domain':domain,'pinned_ip':ip,'round':round_no,'n':n+1,
             'rc':p.returncode,'http':x.get('http_code',0),'local':x.get('local_ip',''),
             'remote':x.get('remote_ip',''),'ssl_verify':x.get('ssl_verify_result')}
        for key in ['time_connect','time_appconnect','time_starttransfer','time_total']:
            row[key+'_ms']=x.get(key,0)*1000
        row['tls_extra_ms']=max(0,row['time_appconnect_ms']-row['time_connect_ms'])
        row['response_wait_ms']=max(0,row['time_starttransfer_ms']-row['time_appconnect_ms'])
        row['valid_source']=row['local']==CONFIG[iface]['ip'] and row['remote']==ip
        if p.stderr:row['error']=p.stderr.strip()[:180]
        emit(row);time.sleep(.55)
    event(stage='https_batch_complete',iface=iface,domain=domain,ip=ip,round=round_no,count=count)


def window():
    global IPs
    for iface in IFACES:
        addr=json.loads(output(['ip','-j','-4','addr','show','dev',iface]))
        ip=next(a['local'] for a in addr[0]['addr_info'] if a['family']=='inet')
        dns_list=output(['nmcli','-g','IP4.DNS','device','show',iface]).splitlines()
        ns=next(x.strip() for x in dns_list if ':' not in x and x.strip())
        CONFIG[iface]={'ip':ip,'dns':ns}
    IPs={d:list(dict.fromkeys(x[4][0] for x in socket.getaddrinfo(d,443,socket.AF_INET,socket.SOCK_STREAM)))[:2] for d in DOMAINS}
    meta={'type':'metadata','host':socket.gethostname(),'interfaces':CONFIG,'common_ipv4':IPs,
          'method':'Two rounds, 15 fresh IPv4 TLS+HEAD samples per server/interface/round; no auth or paid voice API',
          'routes_before':output(['ip','-4','route'])}
    emit(meta);event(stage='start',interfaces=CONFIG,common_ipv4=IPs)
    with cf.ThreadPoolExecutor(max_workers=8) as pings:
        ping_jobs=[]
        for iface in IFACES:
            gw=SITE['network']['cellular_gateway'] if iface==SITE['interfaces']['cellular'] else output(['nmcli','-g','IP4.GATEWAY','dev','show',iface]).splitlines()[0]
            for target,label in [(gw,'LAN_gateway'),('223.5.5.5','public_DNS'),(IPs[DOMAINS[0]][0],'Qwen_server'),(IPs[DOMAINS[1]][0],'Doubao_server')]:
                ping_jobs.append(pings.submit(ping,iface,target,label))
        with cf.ThreadPoolExecutor(max_workers=4) as pool:
            dns_jobs=[pool.submit(dns,iface,d,n) for iface in IFACES for d in DOMAINS for n in range(1,8)]
            for f in dns_jobs:f.result()
        for rnd in [1,2]:
            domains=DOMAINS if rnd==1 else list(reversed(DOMAINS))
            with cf.ThreadPoolExecutor(max_workers=4) as pool:
                jobs=[pool.submit(https,iface,d,ip,rnd) for d in domains for ip in IPs[d] for iface in IFACES]
                for f in jobs:f.result()
            if rnd==1:
                event(stage='between_rounds',seconds=15);time.sleep(15)
        for f in ping_jobs:f.result()
    # A supplementary user-domain sample, separate from the main voice comparison.
    try:
        ip=socket.getaddrinfo('www.ymbot.com',443,socket.AF_INET,socket.SOCK_STREAM)[0][4][0]
        with cf.ThreadPoolExecutor(max_workers=2) as pool:
            jobs=[pool.submit(https,i,'www.ymbot.com',ip,3,8) for i in IFACES]
            for f in jobs:f.result()
    except Exception as e:emit({'type':'supplement_error','error':type(e).__name__})
    emit({'type':'complete','routes_after':output(['ip','-4','route'])})

def main():
    global OUT,FH,IFACES,DOMAINS,SITE,WINDOW
    p=argparse.ArgumentParser();p.add_argument('--request',required=True)
    p.add_argument('--output',required=True);p.add_argument('--windows',type=int,default=3)
    p.add_argument('--pause',type=int,default=30);a=p.parse_args()
    if not 1<=a.windows<=10 or not 0<=a.pause<=300:raise ValueError('Invalid sampling duration')
    SITE=json.loads(Path(a.request).read_text())['config']
    IFACES=[SITE['interfaces']['cellular'],SITE['interfaces']['wifi']]
    DOMAINS=SITE['policy']['health_domains']
    OUT=Path(a.output)
    with OUT.open('w',buffering=1) as FH:
        for WINDOW in range(1,a.windows+1):
            window()
            if WINDOW<a.windows:time.sleep(a.pause)
    os.chmod(OUT,0o600)
    event(stage='all_windows_complete',file=str(OUT))
if __name__=='__main__':main()
