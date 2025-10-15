# passwords.py
"""
Password analyzer with breach-list check, suggestions, and coarse time-to-compromise warnings.
Usage:
  1) Optional: pip install requests
  2) Run: python passwords.py
  3) When prompted, enter a password (the script will NOT print a replacement password;
     it only shows short suggestions like "Try adding: a9@" and a coarse 'time to compromise').
"""

from pathlib import Path
import re
import math
import random
import string

# Try to import requests (used only for downloading lists). If not present, the script still runs.
try:
    import requests
except Exception:
    requests = None

# Primary and fallback URLs for a "top common passwords" list (raw text)
PRIMARY_URL = "https://www.ncsc.gov.uk/static-assets/documents/PwnedPasswordsTop100k.txt"
# Fallback (GitHub SecLists - raw). This is commonly available and useful for demos.
FALLBACK_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt"

LOCAL_TOP_PATH = Path("pwned_top100k.txt")  # downloaded file path (or place your own file here)


def download_top_list(dest: Path = LOCAL_TOP_PATH):
    """Try to download a top-password list. Attempts primary URL, then fallback.
       Writes text to dest. Requires 'requests'."""
    if requests is None:
        raise RuntimeError("The 'requests' library is not installed. Install with: pip install requests")

    tried = []
    for url in (PRIMARY_URL, FALLBACK_URL):
        try:
            print(f"Attempting download from: {url}")
            r = requests.get(url, timeout=30)
            r.raise_for_status()
            dest.write_text(r.text, encoding="utf-8")
            print(f"Saved top-password list to: {dest} (size: {dest.stat().st_size} bytes)")
            return dest
        except Exception as e:
            tried.append((url, str(e)))
            print(f"Download failed from {url}: {e}")
    # if here, both attempts failed
    raise RuntimeError("All download attempts failed. Tried URLs:\n" + "\n".join(f"{u}: {err}" for u, err in tried))


def load_top_list_with_rank(path: Path = LOCAL_TOP_PATH):
    """Load local file and return dict password -> rank (1 = most common)."""
    if not path.exists():
        raise FileNotFoundError(f"{path} not found. Run download_top_list() or place a top-list file there.")
    d = {}
    # file lines are treated as passwords (we take first token)
    for i, ln in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
        ln = ln.strip().split()[0] if ln.strip() else ""
        if ln:
            if ln not in d:  # keep earliest (highest) rank if duplicates
                d[ln] = i
    return d


def entropy_estimate(pw: str) -> float:
    """Estimate entropy in bits using charset size^(length) -> length * log2(charset)."""
    if not pw:
        return 0.0
    lower = bool(re.search(r"[a-z]", pw))
    upper = bool(re.search(r"[A-Z]", pw))
    digit = bool(re.search(r"\d", pw))
    special = bool(re.search(r"[!@#$%^&*(),.?\":{}|<>;'\-\[\]\(\)_+=/\\|`~]", pw))
    charset = 0
    charset += 26 if lower else 0
    charset += 26 if upper else 0
    charset += 10 if digit else 0
    # estimate of symbol count (conservative)
    charset += 32 if special else 0
    if charset <= 0:
        return 0.0
    return len(pw) * math.log2(charset)


def simple_patterns(pw: str):
    """Return quick heuristic pattern labels for common weak patterns."""
    pats = []
    if len(pw) < 8:
        pats.append("short")
    if re.fullmatch(r"\d+", pw):
        pats.append("all-digits")
    if re.fullmatch(r"(.)\1{3,}", pw):  # 4+ repeated characters
        pats.append("repeated-chars")
    if re.search(r"(qwert|asdf|zxcv|1q2w|qaz)", pw.lower()):
        pats.append("keyboard-pattern")
    if re.search(r"\d{4}$", pw):
        pats.append("year-suffix")
    # very common weak base words:
    weak_bases = ("password", "passwd", "admin", "welcome", "letmein", "iloveyou")
    low = pw.lower()
    for b in weak_bases:
        if b in low:
            pats.append(f"contains-{b}")
            break
    return pats


def make_short_suggestion():
    """Produce a short 3-character non-revealing suggestion: lower + digit + symbol."""
    letters = string.ascii_lowercase
    syms = "!@#$%^&*;?"
    return random.choice(letters) + random.choice(string.digits) + random.choice(syms)


def estimate_time_to_compromise(entropy: float, rank: int | None):
    """
    Coarse human-readable heuristic estimate.
    - If present in top lists -> gives rank-based windows (days/weeks/months).
    - Else uses entropy bands.
    NOTE: This is illustrative only, not exact.
    """
    if rank is not None:
        if rank <= 100:
            return "days"
        if rank <= 1000:
            return "days to weeks"
        if rank <= 10000:
            return "weeks"
        if rank <= 100000:
            return "weeks to months"
        return "months (lower risk than top lists)"
    # entropy-based fallback
    if entropy < 30:
        return "days to weeks"
    if entropy < 45:
        return "weeks to months"
    if entropy < 60:
        return "months to years"
    return "many years (hard to brute-force)"


def analyze_password(pw: str, top_dict: dict | None = None):
    """Analyze password. Returns a dict of results (no full password output)."""
    pw_s = pw.strip()
    entropy = entropy_estimate(pw_s)
    pats = simple_patterns(pw_s)

    rank = None
    in_top = False
    if top_dict is not None:
        rank = top_dict.get(pw_s)
        in_top = pw_s in top_dict

    tips = []
    if in_top:
        tips.append("This password appears in public breached lists — do NOT use it.")
    if pats:
        tips.append("Weak pattern detected: " + ", ".join(pats))
    # Suggest short addition if entropy low or present in top lists
    if in_top or entropy < 50:
        suggestion = make_short_suggestion()
        tips.append(f"Try adding: {suggestion}  (suggestion — add these characters somewhere in your password)")
    # Strength label based on entropy bands (simple)
    if entropy < 40:
        strength = "Weak"
    elif entropy < 60:
        strength = "Moderate"
    else:
        strength = "Strong"

    ttc = estimate_time_to_compromise(entropy, rank)

    return {
        # intentionally do NOT return the original password to avoid accidental logging
        "entropy_bits": round(entropy, 2),
        "strength": strength,
        "tips": tips,
        "in_top": in_top,
        "rank": rank,
        "time_to_compromise": ttc
    }


def interactive_main():
    """Interactive CLI flow: tries to load local top list; if not present, prompts to download."""
    print("Password Analyzer — defensive checks only (no password is stored or printed).")
    top = None
    # attempt to load local list
    try:
        top = load_top_list_with_rank()
        print(f"Loaded local top list ({len(top)} entries) for rank-based warnings.")
    except FileNotFoundError:
        print(f"No local toplist found at '{LOCAL_TOP_PATH}'.")
        if requests is not None:
            resp = input("Would you like to try downloading a toplist now? (y/N) ").strip().lower()
            if resp == "y":
                try:
                    download_top_list()
                    top = load_top_list_with_rank()
                    print(f"Loaded downloaded top list ({len(top)} entries).")
                except Exception as e:
                    print("Download or load failed:", e)
                    top = None
        else:
            print("Install 'requests' (pip install requests) to enable automatic download.")

    try:
        while True:
            pw = input("\nEnter password to check (or just press Enter to exit): ")
            if not pw:
                print("Exiting.")
                break
            res = analyze_password(pw, top_dict=top)
            print("\n=== Analysis ===")
            print("Estimated entropy (bits):", res["entropy_bits"])
            print("Strength:", res["strength"])
            if res["in_top"]:
                print(f"!! Warning: This password appears in breached lists (rank: {res['rank']}) !!")
            print("Estimated time to compromise (very coarse):", res["time_to_compromise"])
            if res["tips"]:
                print("\nShort Suggestions (non-revealing):")
                for t in res["tips"]:
                    print("-", t)
            else:
                print("No immediate suggestions. Consider using a password manager + 2FA.")
    except KeyboardInterrupt:
        print("\nInterrupted. Bye.")


if __name__ == "__main__":
    interactive_main()
