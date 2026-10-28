"""Freeze every required column's raw source, projection boundary and evidence."""
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
OUT=ROOT/"artifacts/mdd-026"

def require(ok,message):
    if not ok: raise RuntimeError(message)

def read(path): return json.loads((ROOT/path).read_text(encoding="utf-8"))
def identity(path):
    p=ROOT/path; require(p.is_file(),"evidence/source absent: "+path)
    return {"path":path,"bytes":p.stat().st_size,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}

HEADER={
    "file_id":"explicit snapshot-local ordered DEX catalog ID; no production assigner in current leaf API",
    "string_pool_id":"explicit compatibility catalog ID for native StringPoolIdentity; physical pool sharing must not merge occurrence facts",
    "source_path":"Snapshot source occurrence path/provenance; UTF8 compatibility encoding requires explicit lossless policy",
    "entry_name":"ArchiveInventory MemberIdentity raw_name/name_utf8; raw DEX scope uses explicit entry policy",
    "byte_len":"MetadataFacts.bytes().len() for this logical standard DEX",
    "dex_version":"MetadataFacts.header().version",
    "checksum":"MetadataFacts.header().declared_checksum (verified Adler32)",
    "signature_hex":"MetadataFacts.header().declared_signature_sha1 (verified SHA1)",
    "file_size":"MetadataFacts.header().file_size (standard DEX checked u32 projection)",
    "header_size":"MetadataFacts.header().header_range.byte_length",
    "endian_tag":"validated original little-endian header word at byte40",
    "link_size":"validated original header word at byte44 / link_range length or zero",
    "link_off":"validated original header word at byte48 / link_range offset or zero",
    "map_off":"validated original header word at byte52 / map_list physical item start",
    "data_size":"MetadataFacts.header().data_range.byte_length",
    "data_off":"MetadataFacts.header().data_range.byte_offset",
}
for prefix,table in [("string","string_ids"),("type","type_ids"),("proto","proto_ids"),("field","field_ids"),("method","method_ids"),("class","class_defs")]:
    HEADER[prefix+"_count"]="MetadataFacts.header().tables["+table+"].count"
    HEADER[table+"_off"]="validated original "+table+" header offset / corresponding table range"

CODE={"file_id":"explicit per-occurrence catalog ID","method_idx":"DefinitionFacts actual method definition reference ID; shared body expands once per method owner",
    "code_off":"MethodBody::Present.code_byte_offset bound to CodeFacts physical start",
    "registers_size":"CodeItem.registers_size","ins_size":"CodeItem.ins_size","outs_size":"CodeItem.outs_size",
    "tries_size":"CodeItem.tries.len()","debug_info_off":"CodeItem.debug_info_byte_offset, absent encoded offset0 projects as0",
    "insns_size":"CodeItem.insns_size_code_units (not instruction count)","insns_off":"CodeItem.insns_range.byte_offset",
    "tries_off":"validated insns end plus u16 alignment padding iff tries nonempty; otherwise NULL",
    "handlers_off":"validated tries_off + tries_size*8 iff catch list exists; otherwise NULL"}

def main():
    source=read("conformance/manifests/relations.json")
    required=[r for r in source["relations"] if r.get("required_by_hostlab")]
    require(len(required)==17,"required relation count drifted")
    defs={r["name"]:r for r in read("conformance/relations/definitions.json")["relations"]}
    annotations={r["name"]:r for r in read("conformance/relations/annotation-and-signature.json")["relations"]}
    references={r["name"]:r for r in read("conformance/relations/reference-multiplicity.json")["relations"]}
    entries=[]
    for relation in required:
        name=relation["name"]; columns=[]
        for ordinal,column in enumerate(relation["columns"]):
            col=column["name"]; layers=["inventory","structure"]
            native=""; projection="unassembled_production_relation"; evidence=[]; caveat=[]
            if name=="dex_files":
                require(col in HEADER,"unmapped header column "+col); native=HEADER[col]
                evidence=["artifacts/mdd-020/metadata-conformance.json","artifacts/mdd-026/facts-differential.json"]
                if col in ["file_id","string_pool_id","source_path","entry_name"]: caveat.append("caller catalog/provenance mapping remains separate from validated DEX facts")
            elif name=="strings":
                native={"string_pool_id":"MetadataFacts.string_pool().string_pool_id with occurrence-scoped entity identity",
                    "string_idx":"StringFact.data.string_idx","value":"DexText.utf16_units + raw_mutf8; strict_utf8() only if scalar"}[col]
                evidence=["artifacts/mdd-020/metadata-conformance.json","artifacts/mdd-026/facts-differential.json"]
                if col=="value": caveat.append("legal isolated UTF16 surrogates remain exact raw facts; plain UTF8 projection must fail without replacement")
            elif name=="types":
                native={"file_id":"explicit per-occurrence catalog ID","type_idx":"TypeFact.data.type_idx",
                    "descriptor":"TypeFact.data.descriptor","java_name":"exact descriptor/TypeShape atoms; production types.java_name formatter not exposed by MetadataFacts"}[col]
                evidence=["artifacts/mdd-020/metadata-conformance.json","artifacts/mdd-026/facts-differential.json"]
            elif name in defs:
                mapping={c["name"]:c for c in defs[name]["reference_columns"]}
                require(col in mapping,"definition column missing "+name+"."+col); native=mapping[col]["source_mapping"]
                evidence=["artifacts/mdd-021/definition-conformance.json","artifacts/mdd-021/reference-comparison.json","artifacts/mdd-026/facts-differential.json"]
                if name in ["class_fields","class_methods","class_interfaces"]: projection="production_row_api_available"
                if name=="classes" and col=="source_file": caveat.append("nullable source_file is lossless DexText; non-scalar text must not use lossy UTF8")
                if name=="methods" and col in ["opcode_count","opcode_hex"]:
                    layers.append("code_layout"); native="DefinitionFacts MethodBody binding + CodeItem.instructions(opcode/width/ordinal) + payload/raw insns ranges"
                    caveat.append("DefinitionFacts column gate is intentionally narrow INCOMPLETE_FACTS; CodeFacts native instruction atoms are available and independently checked. Full legacy Methods relation assembly is separate032, not an extra026 prerequisite; insns_size is not opcode_count")
                if name=="methods" and col=="param_descriptors": caveat.append("native ordered parameter_descriptors vector is exact; compatibility UTF8 text serialization is separately unqualified")
                if name=="methods" and col in ["access_flags","method_kind"]: caveat.append("reference-only method has NULL definition facts; native/abstract is an actual definition, not reference-only")
            elif name=="code_items":
                layers.append("code_layout"); require(col in CODE,"unmapped code column "+col); native=CODE[col]
                evidence=["artifacts/mdd-023/instruction-conformance.json","artifacts/mdd-026/facts-differential.json"]
                caveat.append("CodeFacts is physical-item scoped; production method-owned row projection must bind DefinitionFacts and preserve shared-body multiplicity, not use physical ordinal as method ID")
            elif name in annotations:
                layers.append("annotations"); projection="production_row_api_available"
                require(column in annotations[name]["columns"],"annotation frozen schema mismatch "+name+"."+col)
                native="AnnotationFacts explicit "+name+" row projection column "+col
                evidence=["artifacts/mdd-022/annotation-conformance.json","artifacts/mdd-022/probes/oracle-comparison.json","artifacts/mdd-026/facts-differential.json"]
                caveat.append("encoded annotation rows complete independently of prototype parameter-position coverage; only an explicitly requested position/absence scope is blocked by Unknown")
                if name=="annotation_elements" and col=="value_f64": caveat.append("declared Float64 JSON uses finite numbers or NaN/Infinity/-Infinity spellings; original IEEE bits/width live on native EncodedValue, not the display projection")
            elif name in references:
                layers += ["code_layout","references"]; projection="production_row_api_available"
                require(column in references[name]["columns"],"reference frozen schema mismatch "+name+"."+col)
                native="ReferenceFacts explicit "+name+" row projection column "+col
                evidence=["artifacts/mdd-024/reference-conformance.json","artifacts/mdd-024/small-reference-comparison.json","artifacts/mdd-026/facts-differential.json"]
                caveat.append("requires complete encoded-reference method scope; keeps per-site multiplicity and unresolved external targets; does not infer runtime dispatch")
                if name=="method_strings" and col=="value": caveat.append("legal non-scalar UTF16 raw sites complete; plain UTF8 row API returns UNSUPPORTED_QUERY without A0 replacement")
            else: raise RuntimeError("unmapped required relation "+name)
            columns.append({"ordinal":ordinal,**column,"required_layers":layers,"native_atoms":native,
                "native_fact_availability":"available_in_validated_declared_scope", "production_projection":projection,
                "compatibility_profile_admitted":False,"evidence":evidence,"boundaries":caveat})
        entries.append({"name":name,"required_by_hostlab":True,"columns":columns})
    files=["conformance/manifests/relations.json","conformance/relations/definitions.json","conformance/relations/annotation-and-signature.json",
        "conformance/relations/reference-multiplicity.json","conformance/facts/native_probe.rs","conformance/facts/run_probe.py","conformance/facts/verify.py"]
    report={"schema_version":"mdd.required-fact-column-preflight.v1","task":"MDD-026","basis":"complete frozen 17-relation schema; current read-only leaf API review and tiny differential",
        "relation_count":len(entries),"column_count":sum(len(r["columns"]) for r in entries),"relations":entries,"identities":[identity(p) for p in files],
        "global_gates":{"lazy_state_and_retry":"implementation delegated; not qualified by this matrix",
            "scope_required_layers_signer":"implementation delegated; not qualified by this matrix",
            "production_catalog_assignment":"not provided by conformance probe",
            "G1_parser_and_sanitizers":"independent parser gate; not inferred from facts differential",
            "G2_query_equivalence":"requires later QueryIR/SQL execution, not inferred from tiny relation equality"},
        "native_vs_compatibility":"Native atoms and compatibility relation assembly are separate axes; no compatibility formatter is imposed as an extra MDD026 prerequisite. Unknown columns or genuinely absent native atoms cannot pass.",
        "not_task_completion":True}
    HERE.mkdir(parents=True,exist_ok=True);OUT.mkdir(parents=True,exist_ok=True)
    (HERE/"required-columns.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"relations":len(entries),"columns":report["column_count"],"all_columns_mapped":True,"task_complete":False}))

if __name__=="__main__": main()
