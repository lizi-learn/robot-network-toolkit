#!/usr/bin/env python3
"""NRadio LuCI adapter: read only; credentials are read from stdin and never saved."""
from html.parser import HTMLParser
import http.cookiejar
import ipaddress
import json
import re
import sys
import urllib.parse
import urllib.request

class Form(HTMLParser):
    def __init__(self):
        super().__init__();self.values={};self.select=None
    def handle_starttag(self,tag,attrs):
        a=dict(attrs);name=a.get('name')
        if tag=='input' and name:
            typ=a.get('type','text')
            if typ not in ['submit','button','reset'] and (typ not in ['checkbox','radio'] or 'checked' in a):
                self.values[name]=a.get('value','')
        elif tag=='select' and name:self.select=name
        elif tag=='option' and self.select and ('selected' in a or self.select not in self.values):
            self.values[self.select]=a.get('value','')
    def handle_endtag(self,tag):
        if tag=='select':self.select=None

def main():
    req=json.load(sys.stdin);cfg=req['config'];net=cfg['network'];r=cfg['fiveg_router']
    url=r['url'].rstrip('/')
    o=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def read(path,data=None):
        q=urllib.request.Request(url+path,data=None if data is None else urllib.parse.urlencode(data).encode())
        with o.open(q,timeout=10) as response:s=response.read().decode(errors='replace')
        return s
    read('/cgi-bin/luci/',{'luci_username':r.get('username','root'),'luci_password':req['password']})
    paths=['/cgi-bin/luci/nradioadv/network/simpleroutes','/cgi-bin/luci/nradioadv/network/dhcp']
    forms=[]
    for path in paths:
        s=read(path)
        if 'name="luci_password"' in s:raise ValueError('5G router authentication failed')
        f=Form();f.feed(s);forms.append(f.values)
    routes=[];reservations=[]
    wanted=ipaddress.ip_network(net['chassis_cidr']);cell=net['cellular_address'].split('/')[0]
    for key,value in forms[0].items():
        if key.startswith('cbid.network.') and key.endswith('.target'):
            prefix=key[:-len('target')]
            if value==str(wanted.network_address):
                routes.append({'target':value,'gateway':forms[0].get(prefix+'gateway'),
                               'netmask':forms[0].get(prefix+'netmask'),'interface':forms[0].get(prefix+'interface')})
    for key,value in forms[1].items():
        if key.startswith('cbid.dhcp.') and key.endswith('.ip') and value==cell:
            prefix=key[:-2];reservations.append({'address':value,'mac':forms[1].get(prefix+'mac','').lower()})
    good_routes=[x for x in routes if x['gateway']==cell and x['netmask']==str(wanted.netmask) and x['interface']=='lan']
    mac=req.get('cellular_mac','').lower()
    good_reservations=[x for x in reservations if not mac or x['mac']==mac]
    # Read an already deployed route and reservation, without guessing firmware-
    # specific create/delete endpoints or touching unrelated router settings.
    print(json.dumps({'route_ok':len(good_routes)==1,'reservation_ok':len(good_reservations)==1,
                      'target':str(wanted),'gateway':cell,'changed':False,
                      'adapter':'NRadio LuCI read-only guard'},ensure_ascii=False))

if __name__=='__main__':
    try:main()
    except Exception as e:
        print(json.dumps({'error':type(e).__name__+': '+str(e)[:180]}));raise SystemExit(1)
