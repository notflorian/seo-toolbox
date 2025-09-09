#!/usr/bin/env python3
# sitemap_diff.py — Compare <loc> URLs across runs for a list of sitemap XML URLs.
#
# Usage:
#   python sitemap_diff.py /path/to/sitemaps.txt
#   # Optional flags
#   python sitemap_diff.py sitemaps.txt --state-file .sitemap_state.json --no-follow-index --max-print 100
#
# The input file should contain one sitemap URL per line.
# - Empty lines and lines starting with '#' are ignored.
# - Supports http(s) URLs, .xml or .xml.gz, as well as local files like file:///... or plain paths.
#
# What it does:
# - Downloads each sitemap.
# - If it's a sitemap index, it follows child sitemaps (unless --no-follow-index).
# - Extracts every <loc> it finds under <urlset> (i.e. page URLs).
# - Compares with what was saved on the previous run in the state file.
# - Prints added and removed URLs to the console, then updates the state file.
#
# MIT License
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import gzip
import io
import json
import sys
import typing as t
import xml.etree.ElementTree as ET
import re
from urllib.parse import urlparse
from pathlib import Path

try:
    import requests  # type: ignore
except Exception as e:
    print("This script requires the 'requests' package. Install with: pip install requests", file=sys.stderr)
    raise

class FetchResult(t.TypedDict, total=False):
    url: str
    ok: bool
    status: int
    content: bytes
    error: str

StateType = t.Dict[str, t.Any]  # Overall state structure
# {
#   "sitemaps": {
#       sitemap_url: {
#           "urls": list[dict[str, str]],  # each dict: {"loc": str, "lastmod": str (optional)}
#       },
#   },
#   "run_at": str
# }

def _now_utc_iso_z() -> str:
    # RFC3339 UTC with trailing Z
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")

def load_state(path: Path) -> StateType:
    if path.is_file():
        try:
            with path.open("r", encoding="utf-8") as f:
                data: StateType = json.load(f)
                # No normalization needed, just ensure "urls" is a list of dicts
                return data
        except Exception as e:
            print(f"⚠️  Could not read state file {path}: {e}", file=sys.stderr)
    return {"sitemaps": {}, "run_at": None}

def save_state(path: Path, state: StateType) -> None:
    to_save: StateType = {"sitemaps": {}, "run_at": _now_utc_iso_z()}
    for sm, entry in state.get("sitemaps", {}).items():
        urls = entry.get("urls", [])
        to_save["sitemaps"][sm] = {"urls": urls}
    with path.open("w", encoding="utf-8") as f:
        json.dump(to_save, f, indent=2, ensure_ascii=False)

def read_sitemap_list(path: Path) -> list[str]:
    lines: list[str] = []
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            lines.append(line)
    return lines

def is_probably_gz(name_or_url: str, content: bytes, headers: t.Dict[str, str]) -> bool:
    if name_or_url.lower().endswith(".gz"):
        return True
    enc = headers.get("Content-Encoding", "").lower()
    ctype = headers.get("Content-Type", "").lower()
    if "gzip" in enc or "application/x-gzip" in ctype or "application/gzip" in ctype:
        return True
    # magic number
    return content.startswith(b"\x1f\x8b")

def fetch(url: str, timeout: float = 60.0) -> FetchResult:
    # Support local files (file:/// or plain paths)
    parsed = urlparse(url)
    if parsed.scheme in ("file", ""):
        try:
            p = Path(parsed.path if parsed.scheme == "file" else url)
            data = p.read_bytes()
            headers: dict[str, str] = {}
            if is_probably_gz(p.name, data, headers):
                try:
                    data = gzip.decompress(data)
                except Exception:
                    pass
            return {"url": url, "ok": True, "status": 200, "content": data}
        except Exception as e:
            return {"url": url, "ok": False, "error": str(e)}
    try:
        headers = {
            "User-Agent": "sitemap-diff/1.0 (+https://example.com)",
            "Accept": "application/xml,text/xml,application/xhtml+xml;q=0.9,*/*;q=0.8",
        }
        resp = requests.get(url, headers=headers, timeout=timeout)
        content = resp.content or b""
        if resp.status_code == 200 and is_probably_gz(url, content, resp.headers):  # type: ignore[arg-type]
            try:
                content = gzip.decompress(content)
            except Exception:
                pass
        return {"url": url, "ok": bool(resp.ok), "status": int(resp.status_code), "content": content, **({} if resp.ok else {"error": resp.reason})}
    except Exception as e:
        return {"url": url, "ok": False, "error": str(e)}

def _sanitize_xml_bytes(content: bytes) -> bytes:
    import codecs
    if not content:
        return content
    first = content.find(b'<')
    if first > 0:
        content = content[first:]
    if content.startswith(codecs.BOM_UTF8):
        content = content[len(codecs.BOM_UTF8):]
    return content.lstrip()

def _inject_missing_ns(content: bytes) -> bytes:
    # If prefixed tags appear without xmlns:prefix declarations, inject common sitemap namespaces on the root element.
    # Supported: xhtml, image, video, news
    text = content.decode("utf-8", errors="ignore")
    root_match = re.search(r"<(urlset|sitemapindex)\b[^>]*>", text, flags=re.IGNORECASE | re.DOTALL)
    if not root_match:
        return content
    root_tag = root_match.group(0)

    present = set(re.findall(r'xmlns:([a-zA-Z0-9_-]+)\s*=', root_tag))
    used = set(re.findall(r"<\s*([a-zA-Z0-9_-]+):", text))
    needed = used - present

    ns_map = {
        "xhtml": "http://www.w3.org/1999/xhtml",
        "image": "http://www.google.com/schemas/sitemap-image/1.1",
        "video": "http://www.google.com/schemas/sitemap-video/1.1",
        "news":  "http://www.google.com/schemas/sitemap-news/0.9",
    }
    to_inject = {pfx: ns_map[pfx] for pfx in needed if pfx in ns_map}
    if not to_inject:
        return content

    inject_str = "".join([f' xmlns:{pfx}="{uri}"' for pfx, uri in to_inject.items()])
    new_root = root_tag[:-1] + inject_str + ">"
    new_text = text.replace(root_tag, new_root, 1)
    return new_text.encode("utf-8", errors="ignore")

def _lenient_extract_loc_urls(content: bytes) -> list[dict[str, str]]:
    """
    Very lenient extractor: grabs any <loc>...</loc> occurrences, even if the XML is malformed.
    It ignores structure and namespaces. Intended as a last-resort fallback when parsing fails
    with errors like "mismatched tag" or "unbound prefix".
    """
    text = content.decode("utf-8", errors="ignore")
    # Remove anything before first '<' (already done, but safe)
    first = text.find("<")
    if first > 0:
        text = text[first:]
    loc_values = re.findall(r"<\s*loc\b[^>]*>(.*?)</\s*loc\s*>", text, flags=re.IGNORECASE | re.DOTALL)
    urls: list[dict[str, str]] = []
    def _unescape(s: str) -> str:
        return (s.replace("&amp;", "&")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", '"')
                .replace("&apos;", "'"))
    for v in loc_values:
        u = _unescape(v.strip())
        if u:
            urls.append({"loc": u})
    return urls

def parse_xml(content: bytes) -> ET.Element:
    content = _sanitize_xml_bytes(content)
    content = _inject_missing_ns(content)
    return ET.fromstring(content)

def iter_loc_texts(elem: ET.Element) -> t.Iterator[str]:
    # iterate over all descendant elements whose tag endswith 'loc'
    for e in elem.iter():
        tag = e.tag
        if isinstance(tag, str) and tag.endswith("loc"):
            if e.text:
                yield e.text.strip()

def root_tag_name(elem: ET.Element) -> str:
    # returns local name ignoring namespace
    if elem.tag.startswith("{"):
        return elem.tag.split("}", 1)[1]
    return str(elem.tag)

def collect_page_urls_from_urlset(root: ET.Element) -> list[dict[str, str]]:
    urls: list[dict[str, str]] = []
    for url_elem in root.findall(".//{*}url"):
        loc_elem = url_elem.find("{*}loc")
        if loc_elem is not None and loc_elem.text:
            entry = {"loc": loc_elem.text.strip()}
            lastmod_elem = url_elem.find("{*}lastmod")
            if lastmod_elem is not None and lastmod_elem.text:
                entry["lastmod"] = lastmod_elem.text.strip()
            urls.append(entry)
    # Fallback in case namespaces are odd
    if not urls:
        for loc in iter_loc_texts(root):
            urls.append({"loc": loc})
    return urls

def collect_child_sitemaps_from_index(root: ET.Element) -> list[str]:
    # <sitemapindex>/<sitemap>/<loc>
    locs: list[str] = []
    for loc in root.findall(".//{*}sitemap/{*}loc"):
        if loc.text:
            locs.append(loc.text.strip())
    # Fallback
    if not locs:
        locs = list(iter_loc_texts(root))
    return locs

def crawl_sitemap(sitemap_url: str, follow_index: bool, timeout: float, workers: int = 8, verbose: bool = False) -> list[dict[str, str]]:
    """Return a set of page URLs contained in the sitemap (following indexes if requested)."""
    fetched = fetch(sitemap_url, timeout=timeout)
    if not fetched.get("ok"):
        print(f"  ✖ Failed to fetch {sitemap_url} ({fetched.get('status', 0)}): {fetched.get('error')}", file=sys.stderr)
        return []
    try:
        root = parse_xml(fetched["content"])  # type: ignore[index]
    except Exception as e:
        if verbose:
            print(f"  ✖ Failed to parse XML from {sitemap_url}: {e}", file=sys.stderr)
        # Try to salvage by stripping leading bytes (BOM or junk)
        try:
            text = fetched["content"].decode("utf-8", errors="ignore")
            first = text.find("<")
            if first > 0:
                text = text[first:]
            root = ET.fromstring(text)
        except Exception:
            urls = _lenient_extract_loc_urls(fetched["content"])
            if urls:
                if verbose:
                    print(f"  ⚠ Using lenient <loc> extraction for {sitemap_url} (malformed XML).", file=sys.stderr)
                return urls
            return []

    kind = root_tag_name(root).lower()
    if kind == "urlset":
        return collect_page_urls_from_urlset(root)

    if kind == "sitemapindex" and follow_index:
        child_sitemaps = collect_child_sitemaps_from_index(root)
        page_urls: list[dict[str, str]] = []
        # Fetch children concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(crawl_sitemap, sm, False, timeout, workers, verbose): sm for sm in child_sitemaps}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    page_urls.extend(fut.result())
                except Exception as e:
                    sm = futures[fut]
                    print(f"  ✖ Error crawling child sitemap {sm}: {e}", file=sys.stderr)
        return page_urls

    # If unknown structure, try best-effort to gather any <loc>
    return [{"loc": loc} for loc in iter_loc_texts(root)]

def diff(old: list[dict[str, str]], new: list[dict[str, str]]) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]]]:
    old_map = {u["loc"]: u.get("lastmod") for u in old}
    new_map = {u["loc"]: u.get("lastmod") for u in new}
    old_set = set(old_map.keys())
    new_set = set(new_map.keys())
    added_locs = new_set - old_set
    removed_locs = old_set - new_set
    updated_locs = set()
    for loc in (old_set & new_set):
        old_mod = old_map.get(loc)
        new_mod = new_map.get(loc)
        if old_mod and new_mod:
            try:
                dt_old = dt.datetime.fromisoformat(old_mod.replace("Z", "+00:00"))
                dt_new = dt.datetime.fromisoformat(new_mod.replace("Z", "+00:00"))
                if dt_new > dt_old:
                    updated_locs.add(loc)
            except Exception:
                pass
    added = [u for u in new if u["loc"] in added_locs]
    removed = [u for u in old if u["loc"] in removed_locs]
    updated = [u for u in new if u["loc"] in updated_locs]
    return added, removed, updated

def print_changes(sitemap: str, prev_urls: list[dict[str, str]], curr_urls: list[dict[str, str]],
                  max_print: int, verbose: bool) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    added, removed, updated = diff(prev_urls, curr_urls)
    if verbose:
        print(f"\n=== {sitemap} ===")
        print(f"  URLs now: {len(curr_urls)} | Previously: {len(prev_urls)} | +{len(added)} / -{len(removed)}")
        if not added and not removed and not updated:
            print("  No changes.")
        else:
            if added:
                print(f"  Added ({len(added)}):")
                for i, u in enumerate(added):
                    if i >= max_print:
                        print(f"    ... and {len(added)-max_print} more")
                        break
                    print(f"    + {u['loc']}")
            if removed:
                print(f"  Removed ({len(removed)}):")
                for i, u in enumerate(removed):
                    if i >= max_print:
                        print(f"    ... and {len(removed)-max_print} more")
                        break
                    print(f"    - {u['loc']}")
            if updated:
                print(f"  Updated ({len(updated)}):")
                for i, u in enumerate(updated):
                    if i >= max_print:
                        print(f"    ... and {len(updated)-max_print} more")
                        break
                    print(f"    ~ {u['loc']} (lastmod updated)")
    return added, removed

def is_recent(lastmod: str | None, recent_days: int) -> bool:
    if not lastmod:
        return False
    try:
        dt_lastmod = dt.datetime.fromisoformat(lastmod.replace("Z", "+00:00"))
        delta = dt.datetime.now(dt.timezone.utc) - dt_lastmod
        return 0 <= delta.days < recent_days
    except Exception:
        return False

def main() -> int:
    ap = argparse.ArgumentParser(description="Compare <loc> URLs in sitemaps across runs and print changes.")
    ap.add_argument("sitemaps_file", type=Path, help="Text file with one sitemap URL per line.")
    ap.add_argument("--state-file", type=Path, default=Path(".sitemap_state.json"), help="Where to store previous run data.")
    ap.add_argument("--no-follow-index", action="store_true", help="Do not follow <sitemapindex> children.")
    ap.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout per request (seconds).")
    ap.add_argument("--workers", type=int, default=8, help="Max parallel fetches for child sitemaps.")
    ap.add_argument("--max-print", type=int, default=50, help="Max number of URLs to print per added/removed list.")
    ap.add_argument("--verbose", action="store_true", help="Verbose per-sitemap output and final state message.")
    ap.add_argument("--recent-days", type=int, default=7, help="Lookback window in days for default summary (only URLs with lastmod within this window are printed).")
    args = ap.parse_args()

    if not args.sitemaps_file.is_file():
        print(f"Input file not found: {args.sitemaps_file}", file=sys.stderr)
        return 2

    follow_index = not args.no_follow_index
    try:
        sitemaps = read_sitemap_list(args.sitemaps_file)
    except Exception as e:
        print(f"Failed to read sitemap list: {e}", file=sys.stderr)
        return 2
    if not sitemaps:
        print("No sitemaps found in the input file.", file=sys.stderr)
        return 2

    state = load_state(args.state_file)
    state.setdefault("sitemaps", {})

    all_new: list[dict[str, str]] = []
    all_updated: list[dict[str, str]] = []

    for sm in sitemaps:
        prev_entry = state["sitemaps"].get(sm, {})
        prev_urls: list[dict[str, str]] = prev_entry.get("urls", [])
        curr_urls = crawl_sitemap(sm, follow_index, args.timeout, args.workers, args.verbose)
        if curr_urls:
            added, removed, updated = diff(prev_urls, curr_urls)
            print_changes(sm, prev_urls, curr_urls, args.max_print, args.verbose)
            all_new.extend(added)
            all_updated.extend(updated)
            state["sitemaps"][sm] = {"urls": curr_urls}

    save_state(args.state_file, state)
    if args.verbose:
        print(f"\nState saved to {args.state_file}")

    # Filter by recent-days
    recent_new = [u for u in all_new if is_recent(u.get("lastmod"), args.recent_days)]
    recent_updated = [u for u in all_updated if is_recent(u.get("lastmod"), args.recent_days)]

    if recent_new:
        print(f"New URLs ({len(recent_new)} total, lastmod within {args.recent_days} days):")
        for u in recent_new:
            print(u["loc"])
    if recent_updated:
        print(f"Updated URLs ({len(recent_updated)} total, lastmod within {args.recent_days} days):")
        for u in recent_updated:
            print(u["loc"])
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
