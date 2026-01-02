import sys
import re
import ast
import base64
import gzip
import bz2
import io

def clean_noise(content):
    out = []
    i = 0
    n = len(content)

    while i < n:
        if content.startswith("${", i):
            start = i
            i += 2
            depth = 1
            in_dquote = False
            in_squote = False
            inner_start = i

            while i < n and depth > 0:
                c = content[i]
                if not in_squote and c == '"':
                    in_dquote = not in_dquote
                elif not in_dquote and c == "'":
                    in_squote = not in_squote

                if not in_squote and not in_dquote:
                    if c == '{': depth += 1
                    elif c == '}': depth -= 1

                if c == '\\':
                    i += 1

                i += 1

            block = content[start:i]
            inner = content[inner_start:i-1]

            if inner.startswith(('*', '@', '!*', '!@')):
                pass
            else:
                out.append(block)

        elif content.startswith("$@", i) or content.startswith("$*", i):
            i += 2
        else:
            out.append(content[i])
            i += 1

    return "".join(out)

def decode_ansi_c(content):
    out = []
    i = 0
    n = len(content)

    while i < n:
        if content.startswith("$'", i):
            start = i
            i += 2
            acc = ""
            while i < n:
                if content[i] == "'":
                    i += 1
                    break
                if content[i] == '\\':
                    acc += "\\"
                    i += 1
                    if i < n: acc += content[i]
                    i += 1
                else:
                    acc += content[i]
                    i += 1

            try:
                decoded = ast.literal_eval(f"'{acc}'")
                out.append(decoded)
            except:
                out.append(content[start:i])
        else:
            out.append(content[i])
            i += 1
    return "".join(out)

def remove_empty_quotes(content):
    return content.replace('""', '')

def main():
    infile = sys.argv[1] if len(sys.argv) > 1 else 'UDP_menu.sh'
    outfile = sys.argv[2] if len(sys.argv) > 2 else 'UDP_menu_clean.sh'

    try:
        with open(infile, 'r') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Error: {infile} not found.")
        return

    if data.startswith("#!"):
        idx = data.find('\n')
        if idx != -1:
            data = data[idx+1:]

    step1 = clean_noise(data)
    step2 = decode_ansi_c(step1)
    step3 = remove_empty_quotes(step2)

    # Heuristics for Base64 payload
    # Gzip: H4sIA...
    # Bzip2: Qlpo...

    b64_match = re.search(r"'(H4sIA.*?)'", step3)
    bzip_match = re.search(r"'(Qlpo.*?)'", step3)

    b64_data = None
    compression = None

    if b64_match:
        b64_data = b64_match.group(1)
        compression = 'gzip'
    elif bzip_match:
        b64_data = bzip_match.group(1)
        compression = 'bzip2'

    if b64_data:
        print(f"Found Base64 data (length: {len(b64_data)}, compression: {compression})")

        try:
            compressed_data = base64.b64decode(b64_data)
            decompressed = None

            if compression == 'gzip':
                with gzip.GzipFile(fileobj=io.BytesIO(compressed_data)) as gz:
                    decompressed = gz.read()
            elif compression == 'bzip2':
                decompressed = bz2.decompress(compressed_data)

            # Save the decompressed data
            with open(outfile, 'wb') as f:
                f.write(decompressed)

            print(f"Successfully de-obfuscated to {outfile}")

        except Exception as e:
            print(f"Error decoding/decompressing: {e}")

    else:
        print("Could not find base64 payload in the cleaned string.")
        # Debug: print snippet
        print("Snippet of cleaned string (first 500 chars):")
        print(step3[:500])

if __name__ == '__main__':
    main()
