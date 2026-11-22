import base64
import re

# Standard English letter frequency table (%)
ENGLISH_FREQ = {
    'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7,
    's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8,
    'u': 2.8, 'm': 2.4, 'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0,
    'p': 1.9, 'b': 1.5, 'v': 1.0, 'k': 0.8, 'j': 0.15, 'x': 0.15,
    'q': 0.10, 'z': 0.07
}

def caesar_shift(text: str, shift: int) -> str:
    """Shifts alphabetic characters backward by a given offset."""
    result = []
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
        else:
            result.append(char)
    return ''.join(result)

def score_english(text: str) -> float:
    """Scores a string based on English character frequency."""
    return sum(ENGLISH_FREQ.get(char, 0) for char in text.lower())

def solve_caesar(text: str) -> tuple[int, str]:
    """Brute-forces all 25 shifts and returns the best match."""
    best_shift = 0
    best_score = -1.0
    best_text = ""

    for shift in range(1, 26):
        candidate = caesar_shift(text, shift)
        current_score = score_english(candidate)

        # Heuristic boost for standard CTF flag formats
        if any(flag in candidate.lower() for flag in ['flag{', 'ctf{', 'picoctf{']):
            current_score += 100.0

        if current_score > best_score:
            best_score = current_score
            best_shift = shift
            best_text = candidate

    return best_shift, best_text

def smart_decode(cipher: str) -> tuple[str, str]:
    """Identifies the cipher/encoding type and decodes the payload."""
    cipher = cipher.strip()

    # 1. Check for Hexadecimal
    if re.fullmatch(r'[0-9a-fA-F]+', cipher) and len(cipher) % 2 == 0:
        try:
            decoded = bytes.fromhex(cipher).decode('utf-8')
            if decoded.isprintable():
                return "Hexadecimal", decoded
        except Exception:
            pass

    # 2. Check for Base64
    if re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', cipher) and len(cipher) % 4 == 0:
        try:
            decoded = base64.b64decode(cipher).decode('utf-8')
            if decoded.isprintable() and len(decoded) >= 3:
                return "Base64", decoded
        except Exception:
            pass

    # 3. Fallback to Caesar / ROT-N Cryptanalysis
    shift, decoded_caesar = solve_caesar(cipher)
    return f"Caesar / ROT-{shift}", decoded_caesar

if __name__ == "__main__":
    user_input = input("Enter ciphertext: ")
    cipher_type, plain_text = smart_decode(user_input)

    print("-" * 40)
    print(f"[+] Detected Scheme : {cipher_type}")
    print(f"[+] Decoded Output  : {plain_text}")