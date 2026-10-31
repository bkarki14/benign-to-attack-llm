import os, re, json, time, csv, urllib.request

MODEL       = os.environ.get("MODEL", "llama3.1:8b")
K           = int(os.environ.get("K", "2"))
TARGET_ROWS = int(os.environ.get("TARGET_ROWS", "4000"))
MAX_CALLS   = int(os.environ.get("MAX_CALLS", "100000"))
NUM_CTX     = int(os.environ.get("NUM_CTX", "24576"))                      # NEW: was 16384
NUM_PREDICT = int(os.environ.get("NUM_PREDICT", str(K * 2500 + 500)))     # NEW: JSON needs more tokens
TEMP        = float(os.environ.get("TEMPERATURE", "0.8"))
TOP_P       = float(os.environ.get("TOP_P", "0.95"))
SEED_BASE   = int(os.environ.get("SEED_BASE", "0"))
TAG         = os.environ.get("TAG", f"{MODEL.replace(':', '-')}_k{K}")
BASE        = os.environ.get("BASE", "/home/ubuntu/llmdal")
URL         = "http://127.0.0.1:11434/api/generate"

TEMPLATE = open(f"{BASE}/prompts/prompt_attack.txt").read()
ORDER = json.load(open(f"{BASE}/prompts/generation_order.json"))
NF = len(ORDER)
TFS = [5, 6, 7, 8, 9, 10, 11]
TEXT_COLS = {"ip_a", "ip_b", "flow_key", "is_attack"}                     # NEW

# NEW: JSON schema forces exactly these 113 keys with the right types.
# It does NOT force any values - the model still decides every number.
def field_schema(c):
    return {"type": "string"} if c in TEXT_COLS else {"type": ["number", "null"]}
SCHEMA = {"type": "object",
          "properties": {"records": {
              "type": "array", "minItems": K, "maxItems": K,
              "items": {"type": "object",
                        "properties": {c: field_schema(c) for c in ORDER},
                        "required": ORDER, "additionalProperties": False}}},
          "required": ["records"]}

os.makedirs(f"{BASE}/out", exist_ok=True)
CSV_PATH = f"{BASE}/out/{TAG}.csv"
LOG_PATH = f"{BASE}/out/{TAG}.log.jsonl"
RAW_PATH = f"{BASE}/out/{TAG}.raw.txt"

def phase(tf):
    return "attack tail-off" if tf == 11 else "active attack"

def build(tf):
    return (TEMPLATE.replace("{K}", str(K))
                    .replace("{TIMEFRAME}", str(tf))
                    .replace("{PHASE}", phase(tf)))

def call(prompt, seed):
    body = json.dumps({"model": MODEL, "prompt": prompt, "stream": False,
                       "keep_alive": -1, "format": SCHEMA,                    # NEW: format
                       "options": {"num_ctx": NUM_CTX, "num_predict": NUM_PREDICT,
                                   "temperature": TEMP, "top_p": TOP_P,
                                   "repeat_penalty": 1.0, "seed": seed}}).encode()
    req = urllib.request.Request(URL, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=1800) as r:
        return json.loads(r.read())

# NEW: JSON parsing instead of CSV parsing
def cell(v):
    if v is None: return "NA"
    if isinstance(v, bool): return str(v)
    if isinstance(v, float) and v.is_integer(): return str(int(v))
    return str(v)

def parse(text):
    rows, widths = [], []
    try:
        recs = json.loads(text).get("records", [])
    except Exception:
        return rows, [-1]                      # -1 = unparseable JSON
    for r in recs:
        if not isinstance(r, dict): continue
        widths.append(len(r))
        if all(c in r for c in ORDER):
            rows.append([cell(r[c]) for c in ORDER])
    return rows, widths

seen = set()
if os.path.exists(CSV_PATH):
    with open(CSV_PATH) as f:
        rd = csv.reader(f); next(rd, None)
        for r in rd: seen.add(",".join(r))
new_file = not os.path.exists(CSV_PATH)
fout = open(CSV_PATH, "a", newline="")
w = csv.writer(fout)
if new_file: w.writerow(ORDER)

json.dump({"model": MODEL, "k": K, "target_rows": TARGET_ROWS, "max_calls": MAX_CALLS,
           "num_ctx": NUM_CTX, "num_predict": NUM_PREDICT, "temperature": TEMP,
           "top_p": TOP_P, "repeat_penalty": 1.0, "seed_base": SEED_BASE,
           "output": "json-schema (keys+types only)",
           "started": time.strftime("%Y-%m-%d %H:%M:%S")},
          open(f"{BASE}/out/{TAG}.settings.json", "w"), indent=1)

calls, t0 = 0, time.time()
while len(seen) < TARGET_ROWS and calls < MAX_CALLS:
    tf = TFS[calls % len(TFS)]
    calls += 1
    t = time.time()
    try:
        resp = call(build(tf), SEED_BASE + calls)
        text = resp.get("response", "")
    except Exception as e:
        resp, text = {}, ""
        print(f"call {calls} ERROR {e}", flush=True)
    rows, widths = parse(text)
    new = dup = 0
    for r in rows:
        key = ",".join(r)
        if key in seen: dup += 1; continue
        seen.add(key); w.writerow(r); new += 1
    fout.flush()
    with open(RAW_PATH, "a") as f:
        f.write(f"### call {calls} tf={tf}\n{text}\n")
    rec = {"call": calls, "tf": tf, "k": K, "sec": round(time.time() - t, 1),
           "lines": len(widths), "valid": len(rows), "new": new, "dup": dup,
           "widths": widths, "out_tokens": resp.get("eval_count"),
           "prompt_tokens": resp.get("prompt_eval_count"),
           "total_unique": len(seen)}
    with open(LOG_PATH, "a") as f: f.write(json.dumps(rec) + "\n")
    rate = len(seen) / max((time.time() - t0) / 60, 1e-9)
    print(f"{TAG} call {calls} tf={tf} valid {len(rows)}/{K} new {new} "
          f"widths {widths} {rec['sec']}s | unique {len(seen)} | {rate:.2f} rows/min",
          flush=True)
fout.close()
print("DONE", TAG, "unique rows:", len(seen), "calls:", calls)
