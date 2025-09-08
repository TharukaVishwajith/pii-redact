# pii_redactor.py
from __future__ import annotations

import re
import hmac
import hashlib
from typing import Dict, Pattern, Iterable, List, Tuple, Optional

# =============== Optional spaCy (GPU-friendly if available) ===============
try:
    import spacy
    _NLP = None  # will be lazily/explicitly set
    def load_spacy(model: str = "en_core_web_trf", require_gpu: bool = False, gpu_id: int = 0):
        global _NLP
        if require_gpu:
            try:
                spacy.require_gpu(gpu_id)
            except Exception:
                pass  # fall back to CPU silently
        _NLP = spacy.load(model)
except Exception:
    _NLP = None
    def load_spacy(*_, **__):
        # spaCy not available; name redaction via spaCy will be skipped
        return

# ===================== Regex patterns =====================
_PATTERNS: Dict[str, Pattern] = {
    # Emails
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),

    # URLs (basic)
    "URL": re.compile(r"\b(?:https?://|www\.)[^\s<>]+", re.IGNORECASE),

    # IPv4
    "IPV4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),

    # Phone numbers (Sri Lanka + generic spacing)
    "PHONE": re.compile(
        r"""
        (?:
          (?:\+?94|0)                # +94 or leading 0
          [\s\-()]*
          (?:\d[\s\-()]*){9}         # 9 digits with optional separators
        )
        """, re.VERBOSE),

    # Credit card: candidate 13-19 digits with separators (validated by Luhn later)
    "CREDIT_CARD_CAND": re.compile(r"\b(?:\d[ -]?){13,19}\b"),

    # Sri Lanka NIC (old + new)
    "NIC_SL_OLD": re.compile(r"\b\d{9}[VvXx]\b"),
    "NIC_SL_NEW": re.compile(r"\b\d{12}\b"),

    # Sri Lanka(-ish) passports: 1–2 letters + 6–8 digits
    "PASSPORT_SL": re.compile(r"\b[A-Za-z]{1,2}\d{6,8}\b"),

    # NEW: Aeroplan member/card IDs (8–9 digits) near keyword context (±40 chars)
    "AEROPLAN_ID_CTX": re.compile(
        r"""(?ix)
        (?:aeroplan|member|card|account|number|no\.?|redeem|link|register|wallet)
        [^0-9]{0,40}
        (\b\d{8,9}\b)
        |
        (\b\d{8,9}\b)
        [^0-9]{0,40}
        (?:aeroplan|member|card|account|number|no\.?|redeem|link|register|wallet)
        """
    ),

    # NEW: Booking reference / PNR (6 alnum) with context
    "PNR_CTX": re.compile(
        r"""(?ix)
        (?:\bPNR\b|\brecord\s*locator\b|\bbooking\s*(?:ref|reference)\b|\bconfirmation\b|\blocator\b)
        [^A-Z0-9]{0,20}
        ([A-Z0-9]{6})
        |
        ([A-Z0-9]{6})
        [^A-Z0-9]{0,20}
        (?:\bPNR\b|\brecord\s*locator\b|\bbooking\s*(?:ref|reference)\b|\bconfirmation\b|\blocator\b)
        """
    ),

    # Dates (broad coverage)
    "DATE": re.compile(
        r"""(?ix)
        \b(?:\d{1,2}\s*(?:st|nd|rd|th)?\s*
           (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\s*,?\s*\d{2,4})
        | \b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\s+\d{1,2}
           (?:st|nd|rd|th)?\s*,?\s*\d{2,4}?
        | \b\d{4}-\d{1,2}-\d{1,2}\b
        | \b\d{1,2}/\d{1,2}/\d{2,4}\b
        | \b(?:today|tomorrow|yesterday|tonight|this\s+(?:evening|morning|afternoon))\b
        """
    ),

    # City/route pairs (Toronto to Los Angeles, YVR->YYZ, etc.)
    # More restrictive pattern to avoid matching generic words
    "ROUTE": re.compile(
        r"""(?x)
        # Airport codes (3 UPPERCASE letters only, case-sensitive)
        \b([A-Z]{3})\s*(?:to|->|-|—)\s*([A-Z]{3})\b
        |
        # City names with travel context - only with explicit travel keywords
        (?i:(?:from|depart|departing|leaving|origin|fly|flying|travel|traveling|going|book|booking)\s+)
        ([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s+(?:to|->|-|—)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)
        (?=\s+(?:on|in|for|at|by|\d)|[.!?,;]|$)
        """
    ),
}

# Optional NIC context to reduce false positives for plain 12-digit numbers
_REQUIRE_NIC_CONTEXT_FOR_12DIGIT = False
_NIC_CONTEXT = re.compile(r"\bNIC\b", re.IGNORECASE)

# For name hints (titles like Mr./Dr./Name:)
_NAME_HINT = re.compile(
    r"\b(?:Mr\.|Mrs\.|Ms\.|Miss|Dr\.|Prof\.|Name:|Customer:)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\b"
)

# ===================== Helpers =====================
def _luhn_ok(num_str: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", num_str)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    s = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        s += d
    return (s % 10) == 0

def _hash_token(value: str, salt: Optional[str]) -> str:
    if salt is None:
        salt = "change-me-please"
    digest = hmac.new(salt.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
    return digest[:12]  # readable, not reversible

def _mask(value: str, mask_char: str = "•", preserve_length: bool = False) -> str:
    return (mask_char * len(value)) if preserve_length else (mask_char * 6)

def _replacement(value: str, typ: str, strategy: str, mask_char: str, preserve_length: bool, salt: Optional[str]) -> str:
    if strategy == "label":
        return f"[{typ}]"
    elif strategy == "mask":
        return _mask(value, mask_char, preserve_length)
    elif strategy == "hash":
        return f"[{typ}:{_hash_token(value, salt)}]"
    else:
        raise ValueError("strategy must be one of: 'label' | 'mask' | 'hash'")

# Replace the bracket token pattern (handles nested/variant forms)
_BRACKETED_TOKEN = re.compile(
    r"""
    \[+                # one or more opening brackets
    NAME               # literal NAME
    (?::[A-Za-z0-9]+)? # optional :hash
    \]+                # one or more closing brackets
    """, re.VERBOSE
)

# ===================== Core: regex pass =====================
def redact_text_regex(
    text: str,
    strategy: str = "hash",
    mask_char: str = "•",
    preserve_length: bool = False,
    salt: Optional[str] = None,
    enable_types: Optional[Iterable[str]] = None,
) -> str:
    if not text:
        return text
    wanted = set(enable_types) if enable_types else {
        "EMAIL","URL","IPV4","PHONE",
        "CREDIT_CARD","NIC","PASSPORT","NAME_HINT",
        "AEROPLAN_ID","PNR"
    }

    out = text

    # 1) EMAIL
    if "EMAIL" in wanted:
        out = _PATTERNS["EMAIL"].sub(lambda m: _replacement(m.group(0), "EMAIL", strategy, mask_char, preserve_length, salt), out)

    # 2) URL
    if "URL" in wanted:
        out = _PATTERNS["URL"].sub(lambda m: _replacement(m.group(0), "URL", strategy, mask_char, preserve_length, salt), out)

    # 3) IPV4
    if "IPV4" in wanted:
        out = _PATTERNS["IPV4"].sub(lambda m: _replacement(m.group(0), "IPV4", strategy, mask_char, preserve_length, salt), out)

    # 4) PHONE
    if "PHONE" in wanted:
        out = _PATTERNS["PHONE"].sub(lambda m: _replacement(m.group(0), "PHONE", strategy, mask_char, preserve_length, salt), out)

    # 5) CREDIT CARD (validate with Luhn)
    if "CREDIT_CARD" in wanted:
        def repl_cc(m):
            s = m.group(0)
            return _replacement(s, "CREDIT_CARD", strategy, mask_char, preserve_length, salt) if _luhn_ok(s) else s
        out = _PATTERNS["CREDIT_CARD_CAND"].sub(repl_cc, out)

    # 6) NIC (old + new)
    if "NIC" in wanted:
        out = _PATTERNS["NIC_SL_OLD"].sub(lambda m: _replacement(m.group(0), "NIC", strategy, mask_char, preserve_length, salt), out)

        def repl_nic12(m):
            s = m.group(0)
            if _REQUIRE_NIC_CONTEXT_FOR_12DIGIT:
                span = 25
                start = max(0, m.start() - span)
                end = min(len(out), m.end() + span)
                ctx = out[start:end]
                if not _NIC_CONTEXT.search(ctx):
                    return s
            return _replacement(s, "NIC", strategy, mask_char, preserve_length, salt)
        out = _PATTERNS["NIC_SL_NEW"].sub(repl_nic12, out)

    # 7) Passport
    if "PASSPORT" in wanted:
        out = _PATTERNS["PASSPORT_SL"].sub(lambda m: _replacement(m.group(0), "PASSPORT", strategy, mask_char, preserve_length, salt), out)

    # 8) Simple name hints (titles/labels)
    if "NAME_HINT" in wanted:
        out = _NAME_HINT.sub(lambda m: _replacement(m.group(0), "NAME", strategy, mask_char, preserve_length, salt), out)

    # 9) Aeroplan ID (8–9 digits near context)
    if "AEROPLAN_ID" in wanted:
        def repl_aeroplan(m):
            digits = next((g for g in m.groups() if g), None)
            if not digits:
                return m.group(0)
            return m.group(0).replace(digits, _replacement(digits, "AEROPLAN_ID", strategy, mask_char, preserve_length, salt))
        out = _PATTERNS["AEROPLAN_ID_CTX"].sub(repl_aeroplan, out)

    # 10) PNR
    if "PNR" in wanted:
        def repl_pnr(m):
            code = next((g for g in m.groups() if g), None)
            if not code:
                return m.group(0)
            return m.group(0).replace(code, _replacement(code, "PNR", strategy, mask_char, preserve_length, salt))
        out = _PATTERNS["PNR_CTX"].sub(repl_pnr, out)

    return out

# ===================== spaCy PERSON pass =====================
def _sanitize_pre_redacted(text: str) -> str:
    """
    Normalize weird nested tokens like [[NAME:abc]:def] -> [NAME:abc]
    and collapse multiple brackets to a single bracketed token.
    """
    # [[NAME:abc]:def] -> [NAME:abc]
    text = re.sub(r"\[\[NAME:([A-Za-z0-9]+)\]:[A-Za-z0-9]+\]", r"[NAME:\1]", text)
    # Collapse things like [[NAME:abc]] -> [NAME:abc]
    text = re.sub(r"\[\[(NAME(?::[A-Za-z0-9]+)?)\]\]", r"[\1]", text)
    return text

def redact_names_spacy(
    text: str,
    strategy: str = "hash",
    mask_char: str = "•",
    preserve_length: bool = False,
    salt: Optional[str] = None,
    enabled: bool = True
) -> str:
    """
    Redacts PERSON entities via spaCy, catches possessive proper nouns (e.g., Sam's),
    and applies a conservative heuristic to catch missed single/multi-token names
    (e.g., 'Ali', 'Jane Addstart') while avoiding ORG/GPE/LOC.
    Also: masks ROUTE/DATE within any sentence that contains a [NAME:*] token.
    """
    if not enabled or not text:
        return text
    if _NLP is None:
        return text

    text = _sanitize_pre_redacted(text)
    doc = _NLP(text)
    spans: List[Tuple[int,int,str]] = []

    # --- 1) Standard PERSON entities ---
    for ent in doc.ents:
        if ent.label_ == "PERSON":
            chunk = ent.text
            if _BRACKETED_TOKEN.fullmatch(chunk.strip()):
                continue
            repl = _replacement(chunk, "NAME", strategy, mask_char, preserve_length, salt)
            spans.append((ent.start_char, ent.end_char, repl))

    # Helper: check if a character offset is already covered by planned span
    def _covered(start: int, end: int) -> bool:
        for s, e, _ in spans:
            if not (end <= s or start >= e):
                return True
        return False

    # --- 2) Possessive proper nouns missed by NER (e.g., Sam's, James') ---
    for i, tok in enumerate(doc):
        if _BRACKETED_TOKEN.fullmatch(tok.text):
            continue
        if tok.pos_ == "PROPN" and tok.text[:1].isupper() and tok.ent_type_ != "PERSON":
            # Case A: next token is "'s"
            if i + 1 < len(doc) and doc[i+1].text == "'s":
                s, e = tok.idx, tok.idx + len(tok.text)
                if not _covered(s, e):
                    repl = _replacement(tok.text, "NAME", strategy, mask_char, preserve_length, salt)
                    spans.append((s, e, repl))
            # Case B: trailing apostrophe (James')
            elif tok.text.endswith("'") and len(tok.text) > 1 and tok.text[:-1][:1].isupper():
                base = tok.text[:-1]
                s, e = tok.idx, tok.idx + len(base)
                if not _covered(s, e):
                    repl = _replacement(base, "NAME", strategy, mask_char, preserve_length, salt)
                    spans.append((s, e, repl))

    # --- 3) Conservative fallback for missed names (contextual PROPN spans) ---
    PERSON_TRIGGERS = {"customer","passenger","guest","caller","agent",
                       "husband","wife","son","daughter","child","boss",
                       "mother","father","parents","companion","spouse"}

    i = 0
    while i < len(doc):
        tok = doc[i]
        if _BRACKETED_TOKEN.fullmatch(tok.text):
            i += 1
            continue

        # Consider a start if token looks like a proper-name candidate
        is_title = tok.text[:1].isupper() and tok.text[1:].islower()
        is_candidate = (tok.pos_ == "PROPN" or is_title) and tok.is_alpha
        if is_candidate and tok.ent_type_ not in {"PERSON", "ORG", "GPE", "LOC"}:
            # Look for a short span of consecutive similar tokens (max 3)
            j = i
            end_j = i
            count = 0
            while j < len(doc) and count < 3:
                tj = doc[j]
                if _BRACKETED_TOKEN.fullmatch(tj.text):
                    break
                tj_title = tj.text[:1].isupper() and tj.text[1:].islower()
                if (tj.pos_ == "PROPN" or tj_title) and tj.is_alpha and tj.ent_type_ not in {"PERSON","ORG","GPE","LOC"}:
                    end_j = j
                    j += 1
                    count += 1
                else:
                    break

            # Require a nearby person-y trigger to reduce false positives
            left_k = max(0, i - 4)
            left_ctx = {doc[k].text.lower() for k in range(left_k, i)}
            has_trigger = any(t in left_ctx for t in PERSON_TRIGGERS)

            # Also allow if followed by possessive "'s"
            followed_by_pos = (end_j + 1 < len(doc) and doc[end_j + 1].text == "'s")

            if (has_trigger or followed_by_pos) and end_j >= i:
                s = doc[i].idx
                e = doc[end_j].idx + len(doc[end_j])
                text_span = text[s:e]
                if text_span.endswith("'"):
                    base = text_span[:-1]
                    if not _covered(s, s + len(base)):
                        repl = _replacement(base, "NAME", strategy, mask_char, preserve_length, salt)
                        spans.append((s, s + len(base), repl))
                else:
                    if not _covered(s, e):
                        repl = _replacement(text_span, "NAME", strategy, mask_char, preserve_length, salt)
                        spans.append((s, e, repl))
                i = end_j + 1
                continue

        i += 1

    # Apply replacements right-to-left
    out = text
    for s, e, r in sorted(spans, key=lambda x: x[0], reverse=True):
        out = out[:s] + r + out[e:]

    # --- 4) If a sentence contains a [NAME:*] token, also mask ROUTE & DATE in that sentence
    def _mask_routes_dates_when_named(text_in: str) -> str:
        sentences = re.split(r'(?<=[.!?])\s+', text_in)
        for k, s in enumerate(sentences):
            if "[NAME:" in s or "[NAME]" in s:
                s2 = _PATTERNS["ROUTE"].sub(lambda m: _replacement(m.group(0), "ROUTE", strategy, mask_char, preserve_length, salt), s)
                s2 = _PATTERNS["DATE"].sub(lambda m: _replacement(m.group(0), "DATE", strategy, mask_char, preserve_length, salt), s2)
                sentences[k] = s2
        return " ".join(sentences)

    out = _mask_routes_dates_when_named(out)
    return out

# ===================== Unified API =====================
def redact_text(
    text: str,
    strategy: str = "hash",
    mask_char: str = "•",
    preserve_length: bool = False,
    salt: Optional[str] = None,
    enable_types: Optional[Iterable[str]] = None,
    use_spacy_person: bool = True
) -> str:
    """Regex redaction first, then spaCy PERSON NER (optional)."""
    tmp = redact_text_regex(
        text,
        strategy=strategy,
        mask_char=mask_char,
        preserve_length=preserve_length,
        salt=salt,
        enable_types=enable_types
    )
    tmp2 = redact_names_spacy(
        tmp,
        strategy=strategy,
        mask_char=mask_char,
        preserve_length=preserve_length,
        salt=salt,
        enabled=use_spacy_person
    )
    return tmp2

def redact_series(texts: Iterable[str], **kwargs) -> List[str]:
    return [redact_text(t, **kwargs) for t in texts]

def redact_dataframe(
    df,  # pandas.DataFrame, typed loosely to avoid hard dependency here
    text_col: str,
    out_col: Optional[str] = None,
    **kwargs
):
    if out_col is None:
        out_col = f"{text_col}_redacted"
    df2 = df.copy()
    df2[out_col] = df2[text_col].astype(str).map(lambda x: redact_text(x, **kwargs))
    return df2

# ===================== Quick demo =====================
if __name__ == "__main__":
    # Load spaCy model if available (GPU optional)
    try:
        load_spacy(require_gpu=False)  # set True on Colab T4 if you want GPU
    except Exception:
        pass

    sample = (
        "The customer, Sam Altmen, called to book Toronto to Los Angeles Oct 5–14. "
        "PNR ABC123. Aeroplan number 123456789. "
        "Her husband Eli will travel too. The agent Kasun Kalhara."
    )
    print(redact_text(sample, salt="demo-salt"))