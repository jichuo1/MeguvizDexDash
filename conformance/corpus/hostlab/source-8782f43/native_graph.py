"""Raw definitions and Signature annotations from the pinned native backend."""
from dataclasses import dataclass
import re
from native_session import in_list, literal


class UnsupportedAudit(RuntimeError):
    pass


PRIMITIVES = dict(zip("VZBSCIJFD", ("void", "boolean", "byte", "short", "char", "int", "long", "float", "double")))


@dataclass(frozen=True)
class Type:
    raw: str
    generic: tuple = ()

    def __str__(self):
        return self.raw + ("<" + ",".join(map(str, self.generic)) + ">" if self.generic else "")


def parse_type(text, offset=0):
    if offset >= len(text):
        raise UnsupportedAudit("truncated type signature")
    head = text[offset]
    offset += 1
    if head in PRIMITIVES:
        return Type(PRIMITIVES[head]), offset
    if head == "[":
        value, offset = parse_type(text, offset)
        return Type(str(value)+"[]"), offset
    if head in "+-":
        value, offset = parse_type(text, offset)
        return Type(("? extends " if head == "+" else "? super ")+str(value)), offset
    if head == "*":
        return Type("?"), offset
    if head == "T":
        end = text.find(";", offset)
        if end <= offset:
            raise UnsupportedAudit("unterminated type variable")
        return Type(text[offset:end]), end+1
    if head != "L":
        raise UnsupportedAudit("unsupported type signature")
    name, generic = "", []
    while offset < len(text):
        char = text[offset]; offset += 1
        if char == ";":
            return Type(name.replace("/", "."), tuple(generic)), offset
        if char == "<":
            while offset < len(text) and text[offset] != ">":
                value, offset = parse_type(text, offset)
                generic.append(value)
            if offset >= len(text):
                raise UnsupportedAudit("unterminated generic signature")
            offset += 1
        else:
            if char == "." and generic:
                raise UnsupportedAudit("parameterized outer-class signatures require reference analysis")
            name += "$" if char == "." else char
    raise UnsupportedAudit("unterminated class signature")


def method_types(proto):
    if proto.startswith("<"):
        depth, offset = 1, 1
        while depth and offset < len(proto):
            depth += (proto[offset] == "<") - (proto[offset] == ">")
            offset += 1
        proto = proto[offset:]
    if not proto.startswith("("):
        raise UnsupportedAudit("invalid method signature")
    offset, args = 1, []
    while offset < len(proto) and proto[offset] != ")":
        value, offset = parse_type(proto, offset)
        args.append(value)
    if offset >= len(proto):
        raise UnsupportedAudit("unterminated method arguments")
    result, end = parse_type(proto, offset+1)
    # Generic throws signatures follow the return descriptor; their types do not
    # affect the structural rules, but malformed suffixes are never accepted.
    while end < len(proto) and proto[end] == "^":
        _, end = parse_type(proto, end+1)
    if end != len(proto):
        raise UnsupportedAudit("trailing method signature data")
    return args, result


def field_type(signature):
    value, end = parse_type(signature)
    if end != len(signature):
        raise UnsupportedAudit("trailing field signature data")
    return value


def descriptor(name):
    return "L" + name.replace(".", "/") + ";"


@dataclass
class Field:
    name: str
    type: Type
    access: int


@dataclass
class Method:
    owner: str
    name: str
    proto: str
    args: list
    result: Type
    access: int
    file: int
    index: int

    @property
    def ref(self):
        return self.owner, self.name+self.proto


class Graph:
    def __init__(self, session):
        self.session = session
        self.classes = {}
        self.pools = {int(r["file_id"]): int(r["string_pool_id"]) for r in session.rows("SELECT file_id,string_pool_id FROM dex_files ORDER BY file_id")}
        self.signature_ids = {int(r["file_id"]): int(r["type_idx"]) for r in session.rows("SELECT file_id,type_idx FROM types WHERE descriptor='Ldalvik/annotation/Signature;' ORDER BY file_id,type_idx")}

    def signatures(self, classes):
        def conditions(rows, column):
            groups = {}
            for file, value in rows:
                groups.setdefault(file, set()).add(value)
            return " OR ".join("(file_id="+str(file)+" AND "+column+" IN ("+",".join(map(str, sorted(values)))+"))" for file, values in sorted(groups.items()))
        pairs = [(int(c["file_id"]), int(c["class_idx"])) for c in classes]
        entries = self.session.all("SELECT file_id,entry_kind,entry_idx,annotation_set_off FROM annotation_directory_entries WHERE ("+conditions(pairs, "class_idx")+") AND entry_kind IN ('field','method') ORDER BY file_id,entry_kind,entry_idx")
        owners = {}
        for row in entries:
            if row["annotation_set_off"] is not None:
                owners.setdefault((int(row["file_id"]), int(row["annotation_set_off"])), []).append((row["entry_kind"], int(row["entry_idx"])))
        if not owners: return {}
        sets = self.session.all("SELECT file_id,annotation_set_off,annotation_off FROM annotation_set_entries WHERE "+conditions(owners, "annotation_set_off")+" ORDER BY file_id,annotation_set_off,ordinal")
        annotations = {}
        for row in sets:
            file = int(row["file_id"])
            key = file, int(row["annotation_off"])
            annotations.setdefault(key, []).extend(owners[(file, int(row["annotation_set_off"]))])
        annotations = {key: list(dict.fromkeys(values)) for key, values in annotations.items()}
        if not annotations: return {}
        types = self.session.all("SELECT file_id,annotation_off,type_idx FROM annotations WHERE "+conditions(annotations, "annotation_off")+" ORDER BY file_id,annotation_off")
        selected = {key: annotations[key] for r in types if int(r["type_idx"]) == self.signature_ids.get(int(r["file_id"])) for key in [(int(r["file_id"]), int(r["annotation_off"]))]}
        if not selected: return {}
        elements = self.session.all("SELECT file_id,annotation_off,ordinal,value_index FROM annotation_elements WHERE ("+conditions(selected, "annotation_off")+") AND depth=1 AND value_kind='string' ORDER BY file_id,annotation_off,ordinal")
        indices = {}
        for row in elements:
            pool = self.pools[int(row["file_id"])]
            indices.setdefault(pool, set()).add(int(row["value_index"]))
        condition = " OR ".join("(string_pool_id="+str(pool)+" AND string_idx IN ("+",".join(map(str, sorted(values)))+"))" for pool, values in sorted(indices.items()))
        if not condition: return {}
        strings = {(int(r["string_pool_id"]), int(r["string_idx"])): r["value"] for r in self.session.rows("SELECT string_pool_id,string_idx,value FROM strings WHERE "+condition+" ORDER BY string_pool_id,string_idx")}
        result = {}
        for row in elements:
            file = int(row["file_id"])
            for owner in selected[(file, int(row["annotation_off"]))]:
                key = file, *owner
                result[key] = result.get(key, "") + strings[(self.pools[file], int(row["value_index"]))]
        return result

    def prefetch(self, names):
        names = list(dict.fromkeys(n for n in names if n and (n not in self.classes or self.classes[n] and not self.classes[n]["members"])))
        for start in range(0, len(names), 80):
            self.load(names[start:start+80])
        self.hierarchy(names)

    def hierarchy(self, names):
        pending = list(dict.fromkeys(names))
        seen = set()
        while pending:
            unknown = [n for n in pending if n and n not in self.classes and n not in PRIMITIVES.values() and not any(c in n for c in "<>?[]")]
            for start in range(0, len(unknown), 120): self.load_meta(unknown[start:start+120])
            following = []
            for name in pending:
                if not name or name in seen: continue
                seen.add(name)
                node = self.classes.get(name)
                if node: following.extend([node["super"], *node["interfaces"]])
            pending = list(dict.fromkeys(n for n in following if n and n not in seen))

    def load(self, names):
        self.load_meta([name for name in names if name not in self.classes])
        classes = [{"file_id": self.classes[n]["file"], "class_idx": self.classes[n]["idx"]} for n in names if self.classes.get(n)]
        if not classes: return
        condition = in_list(descriptor(n) for n in names)
        signatures = self.signatures(classes)
        for row in self.session.rows("SELECT cf.* FROM class_fields cf WHERE class_descriptor IN ("+condition+") ORDER BY file_id,class_idx,kind,field_idx"):
            name = parse_type(row["class_descriptor"])[0].raw
            sig = signatures.get((int(row["file_id"]), "field", int(row["field_idx"])), row["field_descriptor"].split(":", 1)[-1])
            self.classes[name]["fields"].append(Field(row["field_name"], field_type(sig), int(row["access_flags"])))
        for row in self.session.rows("SELECT cm.* FROM class_methods cm WHERE class_descriptor IN ("+condition+") ORDER BY file_id,class_idx,kind,method_idx"):
            name = parse_type(row["class_descriptor"])[0].raw
            proto = row["method_descriptor"].split("->", 1)[1][len(row["method_name"]):]
            sig = signatures.get((int(row["file_id"]), "method", int(row["method_idx"])), proto)
            args, result = method_types(sig)
            self.classes[name]["methods"].append(Method(name, row["method_name"], proto, args, result,
                int(row["access_flags"]), int(row["file_id"]), int(row["method_idx"])))
        for name in names:
            if self.classes.get(name): self.classes[name]["members"] = True

    def load_meta(self, names):
        if not names:
            return
        condition = in_list(descriptor(n) for n in names)
        classes = self.session.all("SELECT file_id,class_idx,descriptor,access_flags,superclass_descriptor FROM classes WHERE descriptor IN ("+condition+") ORDER BY file_id,class_idx")
        for name in names:
            self.classes[name] = None
        for row in classes:
            name = parse_type(row["descriptor"])[0].raw
            if self.classes.get(name) is not None:
                raise UnsupportedAudit("duplicate class definitions in native structural audit")
            self.classes[name] = {"file": int(row["file_id"]), "idx": int(row["class_idx"]),
                "access": int(row["access_flags"]), "super": parse_type(row["superclass_descriptor"])[0].raw if row["superclass_descriptor"] else None,
                "interfaces": [], "fields": [], "methods": [], "members": False}
        if not classes:
            return
        for row in self.session.rows("SELECT ci.interface_descriptor,c.descriptor FROM class_interfaces ci JOIN classes c ON c.file_id=ci.file_id AND c.class_idx=ci.class_idx WHERE c.descriptor IN ("+condition+") ORDER BY ci.file_id,ci.class_idx,ci.ordinal"):
            self.classes[parse_type(row["descriptor"])[0].raw]["interfaces"].append(parse_type(row["interface_descriptor"])[0].raw)

    def get(self, name):
        if name not in self.classes:
            if name in PRIMITIVES.values() or any(c in name for c in "<>?[]"):
                self.classes[name] = None
            else:
                self.load_meta([name])
        return self.classes[name]

    def full(self, name):
        node = self.get(name)
        if node and not node["members"]: self.load([name])
        return node

    def methods(self, owners, *, inherited=False):
        if inherited:
            self.hierarchy(owners)
            expanded = list(owners)
            for name in owners:
                seen = set()
                while name and name not in seen:
                    seen.add(name)
                    node = self.get(name)
                    name = node["super"] if node else None
                    if name: expanded.append(name)
            self.prefetch(expanded)
        self.prefetch(owners)
        result = []
        for name in owners:
            seen = set()
            while name and name not in seen:
                seen.add(name)
                node = self.full(name)
                if node is None:
                    break
                result.extend(node["methods"])
                name = node["super"] if inherited else None
        return result

    def subclass(self, child, expected):
        if child == expected: return True
        if expected == "android.view.View" and child.startswith(("android.view.", "android.widget.", "android.webkit.")): return True
        if expected == "android.app.Activity" and child.startswith("android.app.") and child.endswith("Activity"): return True
        self.hierarchy([child])
        pending, seen = [child], set()
        while pending:
            name = pending.pop()
            if not name or name in seen:
                continue
            seen.add(name)
            if name == expected:
                return True
            if expected == "android.view.View" and name.startswith(("android.view.", "android.widget.", "android.webkit.")):
                return True
            if expected == "android.app.Activity" and name.startswith("android.app.") and name.endswith("Activity"):
                return True
            node = self.get(name)
            if node:
                pending.extend([node["super"], *node["interfaces"]])
        return False

    def discover(self, result):
        owners = [parse_type(r["class_descriptor"])[0].raw for r in self.session.rows(
            "SELECT DISTINCT m.class_descriptor FROM class_methods c JOIN methods m ON m.file_id=c.file_id AND m.method_idx=c.method_idx WHERE m.return_descriptor="+literal(descriptor(result))+" ORDER BY m.class_descriptor")]
        return self.methods(owners)
