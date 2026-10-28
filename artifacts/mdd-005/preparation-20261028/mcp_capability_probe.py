"""A1 stdio initialization/tool-schema probe, without opening any dataset."""
from pathlib import Path
import asyncio
import hashlib
import json
import sys


async def probe(binary):
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters
    params=StdioServerParameters(command=str(binary),args=['--threads','2','mcp','--timeout-ms','1500','--max-datasets','1'])
    async with asyncio.timeout(10),Client(params) as client:
        server=client.server_info
        tools=[];cursor=None;seen=set()
        while True:
            page=await client.list_tools(cursor=cursor)
            tools.extend(page.tools)
            cursor=page.next_cursor
            if cursor is None:break
            if cursor in seen:raise RuntimeError('MCP tool listing cursor repeated')
            seen.add(cursor)
        if len(tools)!=12:raise RuntimeError('complete actual native MCP tool contract differs')
        rows=[tool.model_dump(mode='json',by_alias=True) for tool in tools]
        query=next(tool for tool in rows if tool['name']=='query')
        return {'schema_version':'mdd.baseline-mcp-capability-probe.v1','binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
                'server_info':server.model_dump(mode='json',by_alias=True),'tool_count':len(rows),'tools':rows,
                'query_compact_schema':query['inputSchema']['properties'].get('compact'),
                'dataset_opened':False,'private_input_parsed':False,'full_audit_qualified':False}


if __name__=='__main__':
    binary=Path(sys.argv[1]).resolve();output=Path(sys.argv[2]);result=asyncio.run(probe(binary))
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({key:result[key] for key in ['server_info','tool_count','query_compact_schema','dataset_opened','full_audit_qualified']}))
