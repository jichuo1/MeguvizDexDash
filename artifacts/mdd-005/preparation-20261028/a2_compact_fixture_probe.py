"""Small synthetic full-page transport equality, not a HostLab/full-audit result."""
from pathlib import Path
import asyncio
import hashlib
import json
import sys


def raw_result(response,compact):
    if response.is_error:raise RuntimeError('native tool error: '+str(response))
    if compact:
        if response.content:raise RuntimeError('compact unexpectedly duplicates content')
        raw=response.structured_content
    else:
        text='\n'.join(getattr(item,'text','') for item in response.content)
        raw=json.loads(text)
    if not isinstance(raw,dict):raise RuntimeError('missing structured native result')
    return raw


def compact_cell(cell):
    # Deliberately finite adapter: this probe admits only tested exact integer,
    # UTF8 text and NULL values. No blanket CAST/bytes/float compatibility claim.
    if cell is None or isinstance(cell,str):return cell
    if isinstance(cell,int) and not isinstance(cell,bool):return str(cell)
    if isinstance(cell,list) and len(cell)==2 and cell[0] in ('i','u') and isinstance(cell[1],str):return cell[1]
    raise RuntimeError('untested compact cell type')


async def consume(client,dataset,sql,compact):
    offset=0;rows=[];columns=None;pages=[];seen=set()
    while True:
        response=await client.call_tool('query',{'dataset_id':dataset,'sql':[sql],'limit':2,'offset':offset,'compact':compact})
        raw=raw_result(response,compact);statement=raw['statements'][0];pages.append(raw)
        names=statement['columns'] if compact else [column['name'] for column in statement['columns']]
        if columns is None:columns=names
        if names!=columns:raise RuntimeError('page schema changed')
        decoded=[[compact_cell(cell) for cell in row] for row in statement['rows']] if compact else [[cell['value'] for cell in row] for row in statement['rows']]
        rows.extend(decoded);next_offset=statement['next_offset']
        if next_offset is None:
            if statement['truncated']:raise RuntimeError('unrecoverable truncated terminal')
            break
        if next_offset in seen or next_offset<=offset:raise RuntimeError('paging did not progress')
        seen.add(next_offset);offset=next_offset
    return {'columns':columns,'rows':rows,'pages':pages,'complete':True}


async def main(binary,fixture,output):
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters
    params=StdioServerParameters(command=str(binary),args=['--threads','2','mcp','--max-datasets','1','--timeout-ms','5000'])
    async with asyncio.timeout(15),Client(params) as client:
        opened=raw_result(await client.call_tool('open_dataset',{'inputs':[str(fixture)]}),False)
        dataset=opened['dataset_id'];results=[]
        try:
            for sql in ["SELECT NULL AS missing, '' AS empty, 'NULL' AS literal_null, 9223372036854775807 AS max_i64 ORDER BY literal_null",
                        'SELECT string_pool_id,string_idx,value FROM strings ORDER BY string_pool_id,string_idx']:
                standard=await consume(client,dataset,sql,False);compact=await consume(client,dataset,sql,True)
                if standard['columns']!=compact['columns'] or standard['rows']!=compact['rows']:raise RuntimeError('full compact DTO differs')
                results.append({'sql':sql,'equivalent':True,'rows':len(standard['rows']),'standard':standard,'compact':compact})
        finally:await client.call_tool('close_dataset',{'dataset_id':dataset})
    record={'schema_version':'mdd.a2-compact-fixture-probe.v1','binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
        'fixture_sha256':hashlib.sha256(fixture.read_bytes()).hexdigest(),'scope':'small synthetic transport only; full pages consumed',
        'private_input_parsed':False,'formal_measurement':False,'full_audit_admitted':False,'results':results}
    output.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'queries':len(results),'row_counts':[r['rows'] for r in results],'complete':True,'full_audit_admitted':False}))


if __name__=='__main__':asyncio.run(main(Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve(),Path(sys.argv[3])))
