"""A0 presentation is compared in this evidence adapter, not core facts."""
import collections
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ANDROID = "http://schemas.android.com/apk/res/android"

def require(ok, message):
    if not ok: raise RuntimeError(message)

def display(attr):
    value, name = attr["value"], attr["name"]["local_name"]
    if value["representation"] == "text": return value["value"]["text"]
    data, decoded = value["raw_data"], value["decoded"]
    # Fixed A0 exposes these framework enum names in a string dictionary.
    # Prove its source rawbits here without embedding presentation in the core.
    if name == "installLocation":
        return {0:"auto", 1:"internalOnly", 2:"preferExternal"}[data]
    if name == "protectionLevel":
        return {0:"normal", 1:"dangerous", 2:"signature", 3:"signatureOrSystem"}[data]
    kind = decoded["kind"]
    if kind == "string": return decoded["value"]["text"]
    if kind == "int_decimal": return str(decoded["signed"])
    if kind == "int_hex": return "0x%08x" % data
    if kind == "boolean": return "true" if data else "false"
    if kind == "unresolved_reference": return ("?" if decoded["attribute"] else "@") + "%08x" % data
    raise RuntimeError("unqualified A0 presentation type: " + kind)

def attrs(node):
    out = {}
    for attr in node["attributes"]:
        uri, name = attr["name"]["namespace_uri"], attr["name"]["local_name"]
        require(uri is None or uri == ANDROID, "new namespace needs explicit comparison policy")
        out[("android:" if uri else "") + name] = display(attr)
    return out

def main():
    pages = json.loads((HERE / "a0/summary-pages.json").read_text(encoding="utf-8"))
    doc = json.loads((HERE / "public-native/stdout.txt").read_text(encoding="utf-8"))["manifests"][0]["document"]
    reference = pages[0]
    all_permissions = []
    cursor = 0
    for index, page in enumerate(pages):
        require(page["offset"] == cursor, "A0 skipped/repeated permission page")
        all_permissions += page["permissions"]
        for key in ["application", "manifest", "uses_sdk", "component_counts", "target_sdk", "total_rows"]:
            require(page[key] == reference[key], "A0 summary changed across permission pages: " + key)
        cursor += len(page["permissions"])
        require(page["next_offset"] == (cursor if index + 1 < len(pages) else None), "A0 terminal cursor mismatch")
    require(not pages[-1]["truncated"] and cursor == reference["total_rows"], "A0 incomplete permission consumption")
    nodes = doc["nodes"]
    actual = {"manifest": attrs(nodes[0]), "application": attrs(nodes[doc["summary"]["application_nodes"][0]]),
              "uses_sdk": attrs(nodes[doc["summary"]["uses_sdk_nodes"][0]]),
              "component_counts": dict(collections.Counter(item["kind"] for item in doc["summary"]["components"])),
              "target_sdk": doc["summary"]["target_sdk_version"]["decoded"]["signed"]}
    actual_permissions = [{"kind": node["name"]["local_name"], "attributes": attrs(node)} for node in nodes
                          if node["parent"] == 0 and node["name"]["namespace_uri"] is None
                          and node["name"]["local_name"] in ["permission", "uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"]]
    for key, value in actual.items(): require(value == reference[key], "A0 full field differs: " + key)
    require(actual_permissions == all_permissions, "A0 full permission order/attributes/multiplicity differs")
    result = {"source": "NewPipe_v0.28.6.apk", "all_required_summary_fields_equal": True,
              "root_attributes":len(actual["manifest"]), "application_attributes":len(actual["application"]),
              "uses_sdk_attributes":len(actual["uses_sdk"]), "components":actual["component_counts"],
              "target_sdk":actual["target_sdk"], "permission_rows":len(actual_permissions),
              "permission_pages":len(pages), "all_pages_consumed":True, "a0_dataset_closed":True,
              "presentation_adapter": {"installLocation:0":"auto", "protectionLevel:2":"signature", "references":"unresolved @8lowerhex"},
              "scope":"full A0 HostLab default get_manifest summary fields for this public input; typed rawbits and complete tree independently verified by manual vectors/AAPT2; no generic XML rendering/MCP equivalence qualification"}
    (HERE / "a0-summary-comparison.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))

if __name__ == "__main__": main()
