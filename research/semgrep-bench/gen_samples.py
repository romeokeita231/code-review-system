import argparse
import os

TS_BLOCK = """export interface Row{ id: number; name: string; }
export class Repo{ rows: Row[] = []; }
export function handler_{i}(req: any, db: any): any {
  const id = req.query.id;
  const rows = db.query("select * from t where id = " + id);
  if (req.body.payload) { exec(req.body.payload); }
  return { status: 200, body: rows };
}
"""

JS_BLOCK = """function handler_{i}(req, db) {
  const id = req.query.id;
  const rows = db.query("select * from t where id = " + id);
  if (req.body.payload) { eval(req.body.payload); }
  return { status: 200, body: rows };
}
"""

PY_BLOCK = """def handler_{i}(req, db):
    ident = req["id"]
    rows = db.query("select * from t where id = " + ident)
    if req["payload"]:
        eval(req["payload"])
    return {"status": 200, "body": rows}
"""


def build(template, target, path):
    chunks = []
    size = 0
    i = 0
    while True:
        block = template.replace("{i}", str(i))
        if size + len(block) > target:
            break
        chunks.append(block)
        size += len(block)
        i += 1
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("".join(chunks))
    return os.path.getsize(path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, help="sample output dir")
    parser.add_argument("--max-bytes", type=int, default=256 * 1024)
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)
    target = args.max_bytes - 8
    sizes = {
        "sample.ts": build(TS_BLOCK, target, os.path.join(args.out, "sample.ts")),
        "sample.js": build(JS_BLOCK, target, os.path.join(args.out, "sample.js")),
        "sample.py": build(PY_BLOCK, target, os.path.join(args.out, "sample.py")),
        "sample_small.ts": build(TS_BLOCK, 2048, os.path.join(args.out, "sample_small.ts")),
    }
    print(sizes)


if __name__ == "__main__":
    main()
