import os, sys, hashlib

def extract(path, out_prefix, ranges, ext='rs'):
    with open(path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    results = []
    for i, (start, end) in enumerate(ranges, 1):
        # start = line number of ```rust (1-indexed), end = line number of closing ``` (1-indexed)
        block = lines[start:end-1]  # lines[start] is line start+1 i.e. first content line
        text = ''.join(block)
        outpath = f"{out_prefix}-{i}.{ext}"
        with open(outpath, 'w', encoding='utf-8') as of:
            of.write(text)
        h = hashlib.sha256(text.encode('utf-8')).hexdigest()
        results.append((outpath, start+1, end-1, h, len(text)))
    return results

def extract_by_order(path, out_prefix, lang, ext):
    """Extract every fenced block whose opening fence is ```<lang>, in order."""
    with open(path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    results = []
    body = None
    for line in lines:
        if body is None:
            if line.rstrip('\n') == '```' + lang:
                body = []
        elif line.rstrip('\n') == '```':
            text = ''.join(body)
            outpath = f"{out_prefix}-{len(results) + 1}.{ext}"
            with open(outpath, 'w', encoding='utf-8') as of:
                of.write(text)
            results.append((outpath, hashlib.sha256(text.encode('utf-8')).hexdigest(), len(text)))
            body = None
        else:
            body.append(line)
    return results

if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[3].startswith('--lang='):
        lang = sys.argv[3][len('--lang='):]
        for r in extract_by_order(sys.argv[1], sys.argv[2], lang, os.environ.get('EXT', lang)):
            print(r)
        sys.exit(0)
    path = sys.argv[1]
    out_prefix = sys.argv[2]
    ranges = []
    args = sys.argv[3:]
    for a in args:
        s,e = a.split(':')
        ranges.append((int(s), int(e)))
    ext = os.environ.get('EXT', 'rs')
    for r in extract(path, out_prefix, ranges, ext):
        print(r)

# Set EXT=json (or another extension) to name the output files
# <out-prefix>-N.<EXT> for non-Rust fenced blocks; the default is rs.
# Usage: python3 extract_listing.py <post.mdx> <out-prefix> <start:end> [<start:end> ...]
# <start> is the line number of the opening ```rust fence (1-indexed);
# <end> is the line number of the closing ``` fence. Both from
# `grep -n '^```' <post.mdx>`. Writes <out-prefix>-1.rs, -2.rs, ... and
# prints (path, first_content_line, last_content_line, sha256, char_len)
# for each, for recording in that crate's PROVENANCE.md.
#
# Order mode, independent of line numbers:
#   python3 extract_listing.py <post.mdx> <out-prefix> --lang=json
# writes <out-prefix>-N.json for the Nth ```json block of the post and
# prints (path, sha256, char_len) for each.
