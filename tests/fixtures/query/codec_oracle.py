"""Independent Python stdlib Base64 oracle, including canonical rejection examples."""
from pathlib import Path
import base64
import json


def main():
    vectors=[bytes(range(n)) for n in range(66)]+[bytes([byte]) for byte in range(256)]
    reject=['A','AAA','_A==',' A==','AA==\n','=AAA','A===','AA==AAAA','AAB=','AB==','AA=A','____']
    result=dict(schema_version='mdd.query-base64-oracle.v1',
                accepted=[dict(bytes=list(v),base64=base64.b64encode(v).decode()) for v in vectors],
                rejected=reject,
                rejection_policy='standard padded RFC4648 alphabet; canonical unused bits; exact length; no whitespace or URL alphabet')
    for item in result['accepted']:
        if base64.b64decode(item['base64'],validate=True)!=bytes(item['bytes']):raise RuntimeError('independent stdlib roundtrip mismatch')
    # Python validate=True does not reject every nonzero pad bit: canonical re-encoding is required.
    for value in reject:
        try:
            decoded=base64.b64decode(value,validate=True)
        except (ValueError,base64.binascii.Error):
            continue
        if base64.b64encode(decoded).decode()==value:raise RuntimeError('negative is actually canonical')
    path=Path(__file__).with_name('codec-cases.json')
    path.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'accepted':len(vectors),'canonical_rejected':len(reject),'oracle':'Python base64 with canonical re-encode'}))


if __name__=='__main__':main()
