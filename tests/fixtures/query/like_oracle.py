"""Native UTF16 wildcard notation, explicitly not a SQLite/DexSQL dialect oracle."""
from pathlib import Path
import json

ROOT=Path(__file__).resolve().parent


def units(text):
    raw=text.encode('utf-16-le','surrogatepass')
    return [int.from_bytes(raw[i:i+2],'little') for i in range(0,len(raw),2)]


def compare(text,pattern,escape):
    tokens=[];at=0
    while at<len(pattern):
        current=pattern[at];at+=1
        if current==escape:
            if at==len(pattern):return 'LIKE_TRAILING_ESCAPE'
            tokens.append(('literal',pattern[at]));at+=1
        elif current==37:tokens.append(('many',None))
        elif current==95:tokens.append(('one',None))
        else:tokens.append(('literal',current))
    if text is None:return None
    # Enumerate all possible consumed prefix lengths; independent of Rust DP and recursive path.
    positions={0}
    for kind,value in tokens:
        if kind=='many':positions={end for begin in positions for end in range(begin,len(text)+1)}
        elif kind=='one':positions={begin+1 for begin in positions if begin<len(text)}
        else:positions={begin+1 for begin in positions if begin<len(text) and text[begin]==value}
    return len(text) in positions


def main():
    manual=[
      ('nul-is-one-unit','\0','_',None,True),
      ('nul-in-middle','a\0z','a_z',None,True),
      ('nul-is-not-terminator','a\0z','a\0',None,False),
      ('isolated-surrogate-one','\ud800','_',None,True),
      ('surrogate-pair-two','\U0001f600','_',None,False),
      ('surrogate-pair-two-matches','\U0001f600','__',None,True),
      ('escaped-percent','%','\\%','\\',True),
      ('escaped-underscore','_','\\_','\\',True),
      ('literal-percent-not-underscore','%','\\_','\\',False),
      ('no-default-escape','\\x','\\_',None,True),
      ('no-default-escape-needs-backslash','_','\\_',None,False),
      ('trailing-explicit-escape','x','x\\','\\','LIKE_TRAILING_ESCAPE'),
      ('trailing-no-escape-is-literal','\\','\\',None,True),
      ('escaped-escape','\\','\\\\','\\',True),
      ('alternate-escape','%','!%','!',True),
      ('nul-escape-unit','%','\0%', '\0',True),
      ('empty-many','','%',None,True),
      ('empty-one','','_',None,False),
      ('unknown-null',None,'%',None,None),
      ('nul-surrogate-many','\0\ud800','%_',None,True),
    ]
    cases=[]
    for name,text,pattern,escape,expected in manual:
        text=None if text is None else units(text);pattern=units(pattern);escape=None if escape is None else units(escape)[0]
        actual=compare(text,pattern,escape)
        if actual!=expected:raise RuntimeError(f'hand expectation differs: {name}')
        cases.append(dict(id=name,text=text,pattern=pattern,escape=escape,expected=expected))
    result=dict(schema_version='mdd.native-like-hand-cases.v1',text_semantics='mdd-text-v1',sql_compatibility_admitted=False,cases=cases)
    (ROOT/'like-cases.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'cases':len(cases),'independent_oracle':'UTF16 consumed-position-set enumeration','sql_compatibility_admitted':False}))


if __name__=='__main__':main()
