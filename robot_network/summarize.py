#!/usr/bin/env python3
"""Summarize benchmark JSONL; omit site addresses, MACs, routes and modem IDs."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import statistics
from check import quantile


def summarize(rows):
    groups=defaultdict(list)
    for row in rows:
        if row.get('type') in ['ping','https','dns']:
            groups[(row['type'],row['iface'],row.get('domain',row.get('label'))) ].append(row)
    results=[]
    for (kind,iface,target),items in sorted(groups.items()):
        result={'type':kind,'interface':iface,'target':target}
        if kind=='ping':
            values=[v for x in items for v in x['rtt_ms']]
            sent=sum(x['sent'] for x in items);received=sum(x['received'] for x in items)
            result.update(sent=sent,received=received,loss_percent=round(100*(sent-received)/sent,3) if sent else None,
                          median_ms=quantile(values,.5),p95_ms=quantile(values,.95),maximum_ms=max(values) if values else None)
        elif kind=='https':
            good=[x for x in items if x['rc']==0 and x['http']>0 and x.get('valid_source')]
            result.update(count=len(items),success=len(good),http_codes=sorted(set(x.get('http',0) for x in items)),
                          tcp_median_ms=quantile([x['time_connect_ms'] for x in good],.5),
                          tcp_p95_ms=quantile([x['time_connect_ms'] for x in good],.95),
                          tls_median_ms=quantile([x['time_appconnect_ms'] for x in good],.5),
                          tls_p95_ms=quantile([x['time_appconnect_ms'] for x in good],.95),
                          total_p95_ms=quantile([x['time_total_ms'] for x in good],.95))
        else:
            good=[x for x in items if not x.get('error') and x.get('rcode')==0 and x.get('answers')]
            result.update(count=len(items),success=len(good),median_ms=quantile([x['elapsed_ms'] for x in good],.5),
                          p95_ms=quantile([x['elapsed_ms'] for x in good],.95))
        results.append(result)
    return results


def main():
    p=argparse.ArgumentParser();p.add_argument('samples');p.add_argument('--output');a=p.parse_args()
    rows=[json.loads(line) for line in Path(a.samples).read_text().splitlines() if line.strip()]
    windows=sorted(set(x['window'] for x in rows))
    result={'start':min(x['observed_at'] for x in rows),'end':max(x['observed_at'] for x in rows),
            'overall':summarize(rows),'windows':{str(w):summarize([x for x in rows if x['window']==w]) for w in windows}}
    result['complete_windows']=[x['window'] for x in rows if x.get('type')=='complete']
    text=json.dumps(result,ensure_ascii=False,indent=2)
    if a.output:Path(a.output).write_text(text+'\n')
    else:print(text)

if __name__=='__main__':main()
