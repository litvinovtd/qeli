"""Source guard for explicit scalar INI defaults and their RU/EN reference tables.

This inspects reader assignments and serde annotations. It does not replace Rust
parsing or qualify runtime behavior; examples also go through the real CLI.
Unsupported expressions and changes to the reader inventory fail closed.
"""
import ast
import operator
import re
import unittest
from decimal import Decimal
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sources=["qeli/src/config/mod.rs","qeli/src/config/server.rs"]
src="\n".join((ROOT/p).read_text(encoding="utf-8") for p in sources)
src=re.sub(r"^\s*//[^\n]*","",src,flags=re.M)
structs={}
for m in re.finditer(r"pub struct (\w+)\s*\{(.*?)^\}",src,re.M|re.S):
 structs[m[1]]={}
 for f in re.finditer(r"((?:#\[[^\]]*\]\s*)*)pub (\w+):\s*(.+?),\s*$",m[2],re.M):
  structs[m[1]][f[2]]={"type":f[3].replace("crate::config::",""),"default_fn":(re.findall(r'default\s*=\s*"([^"]+)"',f[1]) or [None])[0]}
fns={m[1]:m[2].strip() for m in re.finditer(r"fn (default_\w+)\([^)]*\)\s*->[^\{]+\{(.*?)^\}",src,re.M|re.S)}
constants={m[1]:m[2].strip() for m in re.finditer(r"const (\w+):[^=]+=(.*?);",src,re.S)}
udp=(ROOT/"qeli/src/transport_core/udp_buffer.rs").read_text();constants.update({m[1]:m[2].strip() for m in re.finditer(r"const (AUTO_INITIAL_RECV_BYTES):[^=]+=(.*?);",udp,re.S)})
def number(body):
    tree = ast.parse(body, mode="eval").body
    operations = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul}

    def node(n):
        if isinstance(n, ast.Constant) and type(n.value) in (int, float):
            return n.value
        if isinstance(n, ast.BinOp) and type(n.op) in operations:
            return operations[type(n.op)](node(n.left), node(n.right))
        raise ValueError("unsupported arithmetic")

    return str(node(tree))
def value(body):
    body = re.sub(r"//[^\n]*", "", body).strip()
    if body in ("true", "false"):
        return body
    if body in ("String::new()", "Vec::new()"):
        return ""
    match = re.fullmatch(r'"([^"]*)"(?:\.into\(\)|\.to_string\(\))?', body)
    if match:
        return match[1]
    if re.fullmatch(r"[0-9_. *+-]+", body):
        return number(body.replace("_", ""))
    if body.startswith("vec!["):
        strings = re.findall(r'"([^"]*)"', body)
        return ", ".join(strings or re.findall(r"\b[0-9]+\b", body))
    match = re.fullmatch(r"(?:[a-z_]+::)*(\w+)(?:\.into\(\))?", body)
    if match and match[1] in constants:
        return value(constants[match[1]])
    raise ValueError(body)
def walk(typ,path):
    field = structs[typ][path[0]]
    if len(path) > 1:
        return walk(field["type"], path[1:])
    if field["default_fn"]:
        return value(fns[field["default_fn"]])
    field_type = field["type"]
    if field_type == "bool":
        return "false"
    if re.fullmatch(r"[ui]\d+|usize|isize|f32|f64", field_type):
        return "0"
    if field_type == "String" or field_type.startswith(("Option<", "Vec<", "HashMap<")):
        return ""
    enum = re.search(r"pub enum " + re.escape(field_type) + r"\s*\{(.*?)^\}", src, re.M | re.S)
    if enum:
        match = re.search(r'#\[default\]\s*(?:#\[serde\(rename = "([^"]+)"\)\]\s*)?(\w+)', enum[1])
        if match:
            return match[1] or match[2].lower()
    raise ValueError("unresolved type " + field_type)
reader=(ROOT/"qeli/src/config/server_ini.rs").read_text();inventory={}
for sec,fn,typ,var in [("profile","profile_from","ProfileConfig","p"),("auth","auth_from","AuthConfig","a"),("web","web_from","WebConfig","w"),("logging","logging_from","LoggingConfig","l")]:
 body=re.search(r"fn "+fn+r"\([^\{]+\{(.*?)^\}",reader,re.M|re.S)[1]
 if sec=="profile":
  for old,new in (("bo","base.obfuscation"),("o","p.obfuscation"),("bp","base.performance"),("pf","p.performance")):
   body=re.sub(r"\b"+old+r"\.",new+".",body)
 for r in re.finditer(r"\b"+var+r'\.([\w.]+)\s*=\s*s\s*\.\s*(str_or|bool_or|parse_or)\(\s*"([^"]+)"\s*,\s*(?:&)?(?:base\.([\w.]+)|(true|false|[0-9_]+))',body,re.S):
  try:v=walk(typ,r[4].split(".")) if r[4] else r[5];error=None
  except (ValueError,KeyError) as e:v=None;error=str(e)
  inventory[sec+"."+r[3]]={"value":v,"struct":typ,"field":r[1],"accessor":r[2],"error":error}


def documented_scalar_defaults(text):
    section="";active=False;skip=False;tables={}
    for line in text.splitlines():
        if line.startswith("## "):
            section=line
            skip=any(x in line for x in ("Client:","Клиент:","[user:","[group:"))
            active=False
        if not line.startswith("|"):
            active=False
            continue
        cells=[x.strip() for x in re.split(r"(?<!\\)\|",line.strip("|"))]
        if len(cells)>1 and cells[1] in ("Default","Умолч.","По умолчанию","Умолчание","Дефолт"):
            active=True
            continue
        if not active or skip:continue
        keys=[]
        for token in re.findall(r"`([^`]+)`",cells[0]):
            if not re.fullmatch(r"[a-z][a-z0-9_.]*",token):continue
            if "." not in token and keys and "." in keys[-1]:
                token=keys[-1].rsplit(".",1)[0]+"."+token
            keys.append(token)
        if not keys:continue
        root="web" if "[web]" in section else "auth" if "[auth]" in section else "logging" if section in ("## Logging","## Логирование") else "profile"
        tokens=re.findall(r'`[^`]+`|\b(?:on|off)\b|—',cells[1])
        vals=[{"on":"true","off":"false","—":""}.get(t,t.strip("`").strip('"')) for t in tokens]
        if cells[1].startswith(("empty","пуст","(none)","нет")):vals=[""]*len(keys)
        elif "when omitted;" in cells[1] or "при отсутствии ключа;" in cells[1]:vals=vals[:1]
        if len(vals)==1:vals*=len(keys)
        if len(vals)!=len(keys):
            if cells[1].startswith(("empty","пуст","(none)","нет")):vals=[""]*len(keys)
            else:continue
        for key,val in zip(keys,vals):
            # 1 and 1.0 are the same numeric default, not a formatting conflict.
            if re.fullmatch(r"-?[0-9]+(?:\.[0-9]+)?",val):val=str(Decimal(val).normalize())
            tables.setdefault(root+"."+key,set()).add(val)
    return tables


class ServerDefaultDocumentationTests(unittest.TestCase):
    def test_all_explicit_scalar_reader_defaults_match_both_references(self):
        self.assertEqual(len(inventory),138,"update reader extractor/coverage when source changes")
        self.assertFalse({k:v["error"] for k,v in inventory.items() if v["error"]})
        for lang in ("ru","eng"):
            docs=documented_scalar_defaults((ROOT/f"docs/{lang}/manuals/CONFIG.md").read_text(encoding="utf-8"))
            for key,item in inventory.items():
                with self.subTest(lang=lang,key=key):
                    value=item["value"]
                    if re.fullmatch(r"-?[0-9]+(?:\.[0-9]+)?",value):value=str(Decimal(value).normalize())
                    self.assertEqual(docs.get(key),{value},"missing or inconsistent scalar default")


if __name__=="__main__":unittest.main()
