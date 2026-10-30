"""Handwritten small-table expectations plus independent Python materialized oracle."""
from pathlib import Path
import base64
import copy
import json

HERE=Path(__file__).resolve().parent
SNAPSHOT='fixture-snapshot'
EPOCH='18446744073709551615'


def require(condition,message):
    if not condition: raise RuntimeError(message)


def null(): return {'type':'null'}
def integer(n): return {'type':'i64','value':str(n)}
def unsigned(n): return {'type':'u64','value':str(n)}
def text(value):
    raw=value.encode('utf-16-le','surrogatepass')
    return {'type':'utf16','value':[int.from_bytes(raw[i:i+2],'little') for i in range(0,len(raw),2)]}
def blob(value): return {'type':'bytes','value':base64.b64encode(value).decode()}
def entity(dex,index): return {'type':'entity','value':{'snapshot_id':SNAPSHOT,'dex_occurrence_id':dex,'kind':'method_reference','local_index':index}}
def column(name,kind,nullable=False,display=None):return {'id':name,'display_name':display or name,'data_type':kind,'nullable':nullable}
def scan(name):return {'op':'scan','relation':name}
def expr(index):return {'expr':'column','ordinal':index}
def lit(value):return {'expr':'literal','value':value}
def eq(left,right):return {'predicate':'eq','left':left,'right':right}
def where(node,predicate):return {'op':'filter','input':node,'predicate':predicate}
def order(node,keys=None,desc=False):return {'op':'order','input':node,'keys':keys or [{'ordinal':i,'descending':desc if i==1 else False,'nulls_first':not desc} for i in (1,0,2,3)]}
def limit(node,offset,count):return {'op':'limit','input':node,'offset':str(offset),'count':str(count)}
def agg(kind,ordinal,name,ty='u64',nullable=False):return {'kind':kind,'ordinal':ordinal,'column':column(name,ty,nullable)}


L=[
 [integer(1),text('a'),entity('dex-A',0),blob(b'\0')],
 [integer(1),text('a'),entity('dex-A',0),blob(b'\0')],
 [integer(2),null(),entity('dex-A',1),blob(b'')],
 [integer(3),text('a\0z'),entity('dex-B',0),null()],
 [integer(4),text('\ud800'),entity('dex-B',1),blob(b'\0\xff')],
 [integer(5),text('\U0001f600'),null(),null()],
 [integer(6),text('\ue000'),null(),blob(b'')],
]
R=[[entity('dex-A',0),integer(10)],[entity('dex-A',0),integer(20)],
   [entity('dex-B',0),integer(30)],[null(),integer(40)],[entity('dex-A',1),null()]]
TABLES={
 'left':{'columns':[column('id','i64'),column('label','utf16',True),column('entity','entity',True),column('raw','bytes',True)],'required_layers':['structure'],'rows':L},
 'right':{'columns':[column('entity','entity',True),column('number','i64',True)],'required_layers':['structure'],'rows':R},
 'empty':{'columns':[column('id','i64'),column('label','utf16',True),column('entity','entity',True),column('raw','bytes',True)],'required_layers':['structure'],'rows':[]},
 'unbuilt':{'columns':[column('id','i64')],'required_layers':['references'],'rows':[]},
 'overflow':{'columns':[column('n','i64')],'required_layers':['structure'],'rows':[[integer(9223372036854775807)],[integer(1)]]},
}


def query(node,stable=False):return {'schema_version':'mdd.typed-query.v1','text_semantics':'mdd-text-v1','snapshot_id':SNAPSHOT,'catalog_epoch':EPOCH,'require_stable_order':stable,'root':node}


def build():
    cases=[]
    def good(name,node,expected,stable=False):cases.append({'id':name,'query':query(node,stable),'expected_rows':copy.deepcopy(expected),'expected_error':None})
    def bad(name,node,reason,code='INVALID_ARGUMENT',stage='prepare',stable=False):cases.append({'id':name,'query':query(node,stable),'expected_rows':None,'expected_error':{'code':code,'reason':reason,'stage':stage}})
    good('scan-bag',scan('left'),L)
    good('empty-scan',scan('empty'),[])
    good('eq-null-is-unknown',where(scan('left'),eq(expr(1),lit(null()))),[])
    good('is-null',where(scan('left'),{'predicate':'is_null','value':expr(1)}),[L[2]])
    good('duplicate-exact-filter',where(scan('left'),eq(expr(0),lit(integer(1)))),L[:2])
    good('raw-empty-is-not-null',where(scan('left'),{'predicate':'raw_bytes_eq','left':expr(3),'right':lit(blob(b''))}),[L[2],L[6]])
    good('raw-nul-is-not-empty',where(scan('left'),{'predicate':'raw_bytes_eq','left':expr(3),'right':lit(blob(b'\0'))}),L[:2])
    good('prefix-preserves-nul',where(scan('left'),{'predicate':'prefix','value':expr(1),'units':[97]}),[L[0],L[1],L[3]])
    good('like-one-includes-nul',where(scan('left'),{'predicate':'like','value':expr(1),'pattern':[{'token':'literal','value':97},{'token':'any_one'},{'token':'literal','value':122}]}),[L[3]])
    good('like-one-is-one-utf16-unit',where(scan('left'),{'predicate':'like','value':expr(1),'pattern':[{'token':'any_one'}]}),[L[0],L[1],L[4],L[6]])
    good('like-many-plus-one',where(scan('left'),{'predicate':'like','value':expr(1),'pattern':[{'token':'any_many'},{'token':'any_one'}]}),[L[i] for i in (0,1,3,4,5,6)])
    good('false-or-unknown-not-selected',where(scan('left'),{'predicate':'or','left':eq(expr(0),lit(integer(999))),'right':eq(expr(1),lit(null()))}),[])
    good('not-unknown-stays-unknown',where(scan('left'),{'predicate':'not','value':eq(expr(1),lit(null()))}),[])
    good('set-duplicates-do-not-multiply-rows',{'op':'select_ids','input':scan('left'),'ordinal':0,'ids':[integer(1),integer(1),integer(3)]},[L[0],L[1],L[3]])
    join={'op':'equi_join','left':scan('left'),'right':scan('right'),'left_keys':[2],'right_keys':[0],'kind':'inner'}
    joined=[L[0]+R[0],L[0]+R[1],L[1]+R[0],L[1]+R[1],L[2]+R[4],L[3]+R[2]]
    good('join-entity-keeps-dex-and-multiplicity',join,joined)
    leftjoin=copy.deepcopy(join);leftjoin['kind']='left'
    good('left-join-null-never-equals-null',leftjoin,joined+[L[i]+[null(),null()] for i in (4,5,6)])
    emptyjoin=copy.deepcopy(leftjoin);emptyjoin['left']=scan('empty')
    good('empty-left-join',emptyjoin,[])
    global_aggs=[agg('count_star',None,'all'),agg('count',1,'nonnull'),agg('sum',0,'sum','i64',True),agg('min',0,'min','i64',True),agg('max',0,'max','i64',True)]
    good('global-aggregate-bag',{'op':'aggregate','input':scan('left'),'group_by':[],'aggregates':global_aggs},[[unsigned(7),unsigned(6),integer(22),integer(1),integer(6)]])
    good('global-aggregate-empty-still-one-row',{'op':'aggregate','input':scan('empty'),'group_by':[],'aggregates':global_aggs},[[unsigned(0),unsigned(0),null(),null(),null()]])
    good('group-null-once-and-preserve-duplicates',{'op':'aggregate','input':scan('left'),'group_by':[1],'aggregates':[agg('count_star',None,'all'),agg('count',1,'nonnull'),agg('sum',0,'sum','i64',True)]},[[null(),unsigned(1),unsigned(0),integer(2)],[text('a'),unsigned(2),unsigned(2),integer(2)]]+[[L[i][1],unsigned(1),unsigned(1),L[i][0]] for i in (3,4,5,6)])
    ordered=[L[i] for i in (2,0,1,3,4,5,6)]
    good('utf16-total-order',order(scan('left')),ordered,True)
    good('descending-keeps-null-policy',order(scan('left'),desc=True),[L[i] for i in (6,5,4,3,0,1,2)],True)
    good('ordered-limit-is-relation-operator',limit(order(scan('left')),2,3),ordered[2:5],True)
    good('zero-limit',limit(order(scan('left')),0,0),[],True)
    good('duplicate-display-names',{'op':'project','input':limit(scan('left'),0,1),'columns':[{'column':column('first','utf16',True,'duplicate'),'expression':expr(1)},{'column':column('second','i64',False,'duplicate'),'expression':expr(0)}]},[[text('a'),integer(1)]])
    good('lossless-integer-and-null-codec',{'op':'project','input':limit(scan('left'),0,1),'columns':[{'column':column('min','i64'),'expression':lit(integer(-9223372036854775808))},{'column':column('max','u64'),'expression':lit(unsigned(18446744073709551615))},{'column':column('empty','bytes'),'expression':lit(blob(b''))},{'column':column('missing','bytes',True),'expression':lit(null())}]},[[integer(-9223372036854775808),unsigned(18446744073709551615),blob(b''),null()]])
    bad('eq-has-no-implicit-cast',where(scan('left'),eq(expr(0),lit(text('1')))),'COMPARISON_TYPE_MISMATCH')
    bad('raw-bytes-requires-explicit-predicate',where(scan('left'),eq(expr(3),lit(blob(b'')))),'USE_RAW_BYTES_EQ')
    bad('bad-column-ordinal',where(scan('left'),eq(expr(9),lit(integer(1)))),'COLUMN_ORDINAL')
    foreign=entity('dex-A',0);foreign['value']['snapshot_id']='other-snapshot'
    bad('foreign-entity-even-empty-input',where(scan('empty'),eq(expr(2),lit(foreign))),'ENTITY_OUTSIDE_SNAPSHOT')
    bad('unbuilt-empty-layer-is-not-empty-success',limit(scan('unbuilt'),0,0),'references','INCOMPLETE_FACTS')
    bad('limit-addition-overflow',limit(scan('left'),18446744073709551615,1),'LIMIT_RANGE_OVERFLOW')
    bad('stable-requires-total-order',scan('left'),'TOTAL_ORDER_REQUIRED',stable=True)
    bad('partial-order-not-total',order(scan('left'),[{'ordinal':1,'descending':False,'nulls_first':True}]),'TOTAL_ORDER_REQUIRED',stable=True)
    bad('numeric-sum-typechecked',{'op':'aggregate','input':scan('left'),'group_by':[],'aggregates':[agg('sum',1,'sum','i64',True)]},'SUM_NUMERIC_TYPE')
    bad('sum-overflow-is-error',{'op':'aggregate','input':scan('overflow'),'group_by':[],'aggregates':[agg('sum',0,'sum','i64',True)]},'SUM_OVERFLOW',stage='execute')
    return {'schema_version':'mdd.hand-query-cases.v1','snapshot_id':SNAPSHOT,'catalog_epoch':EPOCH,'ready_layers':['metadata','structure'],'tables':TABLES,'cases':cases}


def raw(value):
    kind=value['type']
    if kind=='null':return None
    value=value['value']
    if kind in ('i64','u64'):return int(value)
    if kind=='utf16':return tuple(value)
    if kind=='bytes':return base64.b64decode(value,validate=True)
    if kind=='entity':return (value['snapshot_id'],value['dex_occurrence_id'],value['kind'],value['local_index'])
    return value


def expression(e,row):
    return row[e['ordinal']] if e['expr']=='column' else e['value']


def predicate(p,row):
    op=p['predicate']
    if op in ('eq','raw_bytes_eq'):
        a,b=raw(expression(p['left'],row)),raw(expression(p['right'],row))
        return None if a is None or b is None else a==b
    if op=='is_null':return raw(expression(p['value'],row)) is None
    if op=='prefix':
        value=raw(expression(p['value'],row));return None if value is None else value[:len(p['units'])]==tuple(p['units'])
    if op=='like':
        value=raw(expression(p['value'],row))
        if value is None:return None
        reachable={0}
        for token in p['pattern']:
            if token['token']=='any_many':reachable={i for start in reachable for i in range(start,len(value)+1)}
            elif token['token']=='any_one':reachable={i+1 for i in reachable if i<len(value)}
            else:reachable={i+1 for i in reachable if i<len(value) and value[i]==token['value']}
        return len(value) in reachable
    if op=='not':
        value=predicate(p['value'],row);return None if value is None else not value
    left,right=predicate(p['left'],row),predicate(p['right'],row)
    if op=='and':return False if left is False or right is False else True if left is True and right is True else None
    if op=='or':return True if left is True or right is True else False if left is False and right is False else None
    raise RuntimeError('oracle unknown predicate')


def oracle(node,tables):
    op=node['op']
    if op=='scan':return copy.deepcopy(tables[node['relation']]['rows'])
    if op=='equi_join':
        left,right=oracle(node['left'],tables),oracle(node['right'],tables);out=[]
        for l in left:
            matches=[r for r in right if all(raw(l[a]) is not None and raw(r[b]) is not None and raw(l[a])==raw(r[b]) for a,b in zip(node['left_keys'],node['right_keys']))]
            out.extend([l+r for r in matches])
            if not matches and node['kind']=='left':out.append(l+[null()]*len(tables['right']['columns']))
        return out
    rows=oracle(node['input'],tables)
    if op=='filter':return [r for r in rows if predicate(node['predicate'],r) is True]
    if op=='select_ids':return [r for r in rows if any(r[node['ordinal']]==v for v in node['ids'])]
    if op=='project':return [[expression(c['expression'],r) for c in node['columns']] for r in rows]
    if op=='limit':return rows[int(node['offset']):int(node['offset'])+int(node['count'])]
    if op=='order':
        # Stable repeated-key sorting; no shared Rust comparator or lookup/index implementation.
        for key in reversed(node['keys']):
            nonnull=[r for r in rows if raw(r[key['ordinal']]) is not None];nulls=[r for r in rows if raw(r[key['ordinal']]) is None]
            nonnull.sort(key=lambda r:raw(r[key['ordinal']]),reverse=key['descending'])
            rows=nulls+nonnull if key['nulls_first'] else nonnull+nulls
        return rows
    if op=='aggregate':
        groups={}
        for r in rows:groups.setdefault(tuple(json.dumps(r[i],sort_keys=True) for i in node['group_by']),[]).append(r)
        if not rows and not node['group_by']:groups[()]=[]
        result=[]
        for grouped in groups.values():
            row=[grouped[0][i] for i in node['group_by']]
            for a in node['aggregates']:
                values=[r[a['ordinal']] for r in grouped if a['ordinal'] is not None and raw(r[a['ordinal']]) is not None]
                if a['kind']=='count_star':value=unsigned(len(grouped))
                elif a['kind']=='count':value=unsigned(len(values))
                elif not values:value=null()
                elif a['kind']=='sum':value={'type':a['column']['data_type'],'value':str(sum(raw(v) for v in values))}
                else:value=(min if a['kind']=='min' else max)(values,key=raw)
                row.append(value)
            result.append(row)
        result.sort(key=lambda r:tuple((v['type']!='null',raw(v)) for v in r[:len(node['group_by'])]))
        return result
    raise RuntimeError('oracle unknown operator')


def main():
    data=build();checked=0
    for case in data['cases']:
        if case['expected_error'] is None:
            actual=oracle(case['query']['root'],data['tables'])
            require(actual==case['expected_rows'],f"manual expectation differs from independent oracle: {case['id']}")
            checked+=1
    (HERE/'cases.json').write_text(json.dumps(data,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'cases':len(data['cases']),'manual_positive_oracle_comparisons':checked,
                      'negative_cases':'hand-adjudicated, Rust must execute exact failure stage/reason',
                      'independence':'Python handwritten lists/arithmetic/sets/stable sorting, no production parser or SQLite'}))


if __name__=='__main__':main()
