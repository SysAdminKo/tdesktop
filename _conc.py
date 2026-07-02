import json, collections
path=r'd:/GitHub/tdesktop/debug-4ce049.log'
inf=[]      # (t, dc, parts, sessions, warm)
for l in open(path,encoding='utf-8',errors='replace'):
    l=l.strip()
    if not l: continue
    try: o=json.loads(l)
    except: continue
    if o.get('event')=='inflight':
        inf.append((o.get('t'),o.get('dc'),o.get('inflightParts'),o.get('sessions'),o.get('warmSessions'),o.get('clock')))
print('inflight samples=%d'%len(inf))
if inf:
    parts=[x[2] for x in inf]
    ps=sorted(parts); n=len(ps)
    print('inflightParts p50=%d p90=%d p99=%d max=%d'%(ps[int(n*.5)],ps[int(n*.9)],ps[min(n-1,int(n*.99))],ps[-1]))
    print('distribution of inflightParts:',dict(sorted(collections.Counter(parts).items())))
    print('sessions seen:',dict(sorted(collections.Counter(x[3] for x in inf).items())))
    print('warmSessions seen:',dict(sorted(collections.Counter(x[4] for x in inf).items())))
    # peak window
    top=sorted(inf,key=lambda x:-x[2])[:10]
    print('--- top10 concurrency moments ---')
    for t,dc,p,s,w,clk in top:
        print('  %s dc=%s parts=%d sessions=%s warm=%s'%(clk,dc,p,s,w))
