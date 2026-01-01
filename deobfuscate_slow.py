import re
import base64
import gzip
import sys
import io

def deobfuscate(filepath):
    print(f"Reading {filepath}...")
    with open(filepath, 'r') as f:
        content = f.read()

    # Pattern to match ${...} handling escaped braces inside
    pattern_braces = r'\$\{(?:[^}]|\\\})*\}'
    # Pattern to match "${...}"
    pattern_quoted_braces = r'"\$\{(?:[^}]|\\\})*\}"'
    # Pattern for simple $@, $*
    pattern_simple = r'\$[@*]'
    # Pattern for quoted simple "$@"
    pattern_quoted_simple = r'"\$[@*]"'
    # Pattern for empty quotes ""
    pattern_empty_quotes = r'""'
    # Pattern for $!
    pattern_bang = r'\$!'

    # Remove the noise
    cleaned = re.sub(pattern_quoted_braces, '', content)
    cleaned = re.sub(pattern_braces, '', cleaned)
    cleaned = re.sub(pattern_quoted_simple, '', cleaned)
    cleaned = re.sub(pattern_simple, '', cleaned)
    cleaned = re.sub(pattern_empty_quotes, '', cleaned)
    cleaned = re.sub(pattern_bang, '', cleaned)

    # Remove all whitespace to make pattern matching easier
    cleaned_nospace = re.sub(r'\s+', '', cleaned)

    print(f"Cleaned string length: {len(cleaned_nospace)}")
    print(f"Preview: {cleaned_nospace[:200]}...")

    # Look for printf pattern.
    # Based on previous output: +<b^*}"e"\v\al"$(Zift}'p'\r\i''ntf"Y2xlYXIgIApybSA...
    # It seems 'printf' was also obfuscated with quotes like 'p'\r\i''ntf
    # Let's clean up quotes from the string too to find the command easier.

    # Remove single and double quotes to reveal the command structure
    # This assumes the base64 string doesn't rely on quotes for integrity or we can reconstruct it.
    # Actually, the base64 string is likely quoted.

    # Let's try to find the largest contiguous alphanumeric block. Base64 is usually long.
    # The previous preview showed "Y2xlYXIgIApybSA...".

    # Regex for a long base64 string (alphanumeric + +/ + =)
    # We look for something reasonably long, say > 100 chars.
    base64_candidates = re.findall(r'[A-Za-z0-9+/=]{100,}', cleaned_nospace)

    if not base64_candidates:
        print("No obvious long Base64 strings found.")
        return cleaned_nospace

    print(f"Found {len(base64_candidates)} candidate blobs.")

    # Try decoding the longest one
    longest_candidate = max(base64_candidates, key=len)
    print(f"Longest candidate length: {len(longest_candidate)}")
    print(f"Candidate preview: {longest_candidate[:50]}...")

    try:
        decoded_bytes = base64.b64decode(longest_candidate)
        print(f"Base64 decode successful. Size: {len(decoded_bytes)} bytes")

        # Check for GZIP
        if decoded_bytes.startswith(b'\x1f\x8b'):
            print("GZIP signature found. Decompressing...")
            with gzip.GzipFile(fileobj=io.BytesIO(decoded_bytes)) as gz:
                return gz.read().decode('utf-8')
        else:
            return decoded_bytes.decode('utf-8')

    except Exception as e:
        print(f"Decode failed: {e}")
        return longest_candidate

if __name__ == "__main__":
    result = deobfuscate('slow.sh')

    mode = 'w' if isinstance(result, str) else 'wb'

    with open('slow_clean.sh', mode) as f:
        f.write(result)
    print(f"Output written to slow_clean.sh (mode={mode})")
