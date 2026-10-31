"""Build the description-only prompt from the Setting A prompt.

Setting 0 (description-only) = Setting A with the benign-statistics block removed.
Nothing else changes except section renumbering, so Setting A minus Setting 0 is
exactly the benign information. Every rule kept here also appears in the Setting B
prompt (mined from attack traffic), so it describes the monitoring setup, not one class.

Usage: python3 build_prompt_desc_only.py prompts/settingA_benign_stats.txt prompts/description_only.txt
"""
import re
import sys

src, dst = sys.argv[1], sys.argv[2]
text = open(src, encoding="utf-8").read()

# 1) Drop section 2 (benign statistics) up to the attack section header.
start = text.index("2. WHAT NORMAL TRAFFIC LOOKS LIKE HERE")
end = text.index("3. THE ATTACK TO SIMULATE")
text = text[:start] + text[end:]

# 2) The attack section pointed back at the removed benign block.
old = ("Think about how such a flood would look in this network compared with "
       "the normal traffic above, and choose values accordingly.")
assert old in text
text = text.replace(old, "Think about how such a flood would look in this network, "
                         "and choose values accordingly.")

# 3) One empty-value clause is benign-only: in attack traffic (Setting B) the INT
#    fields are always filled, so "may be NA only when pkts_fwd <= 2" is a pattern
#    of benign rows. Keep the part both settings share (all filled or all NA).
old = ("are either all filled or all NA; they may be NA only when pkts_fwd is 2 or less. "
       "When filled, mean_hop_count is 1.")
assert old in text
text = text.replace(old, "are either all filled or all NA. When filled, mean_hop_count is 1.")

# 4) Renumber sections 3-7 -> 2-6, and the cross-reference to the field list.
for n in range(3, 8):
    text = re.sub(rf"(?m)^{n}\. (?=[A-Z][A-Z ]+\b)", f"{n - 1}. ", text)
assert "fields of section 4 as keys" in text
text = text.replace("fields of section 4 as keys", "fields of section 3 as keys")

# Placeholders the driver fills must survive untouched.
for p in ("{K}", "{TIMEFRAME}", "{PHASE}"):
    assert p in text, p

open(dst, "w", encoding="utf-8").write(text)
print(f"wrote {dst}")
