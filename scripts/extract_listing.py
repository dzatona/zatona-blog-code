import sys, hashlib

def extract(path, out_prefix, ranges):
    with open(path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    results = []
    for i, (start, end) in enumerate(ranges, 1):
        # start = line number of ```rust (1-indexed), end = line number of closing ``` (1-indexed)
        block = lines[start:end-1]  # lines[start] is line start+1 i.e. first content line
        text = ''.join(block)
        outpath = f"{out_prefix}-{i}.rs"
        with open(outpath, 'w', encoding='utf-8') as of:
            of.write(text)
        h = hashlib.sha256(text.encode('utf-8')).hexdigest()
        results.append((outpath, start+1, end-1, h, len(text)))
    return results

if __name__ == '__main__':
    path = sys.argv[1]
    out_prefix = sys.argv[2]
    ranges = []
    args = sys.argv[3:]
    for a in args:
        s,e = a.split(':')
        ranges.append((int(s), int(e)))
    for r in extract(path, out_prefix, ranges):
        print(r)

# Usage: python3 extract_listing.py <post.mdx> <out-prefix> <start:end> [<start:end> ...]
# <start> is the line number of the opening ```rust fence (1-indexed);
# <end> is the line number of the closing ``` fence. Both from
# `grep -n '^```' <post.mdx>`. Writes <out-prefix>-1.rs, -2.rs, ... and
# prints (path, first_content_line, last_content_line, sha256, char_len)
# for each, for recording in that crate's PROVENANCE.md.
