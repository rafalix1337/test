#!/usr/bin/env python3
"""
Upload local documents (Markdown / HTML) to Confluence Cloud.

One run = one target location: a space, a parent page and (optionally) one AWS
account id. What varies per file is only the page title, taken from PAGE_MAP.

The API token is read from an environment variable, never from the command line.

Examples
--------
    export CONFLUENCE_API_TOKEN='...'
    export CONFLUENCE_USER='you@example.com'

    # dry run - resolves titles, makes no API calls
    python3 confluence_upload.py -p ./reports --space CLOUD --account-id 023414512345 --dry-run

    # real upload, everything nested under the page titled "023414512345"
    python3 confluence_upload.py -p ./reports --space CLOUD --account-id 023414512345 \\
        --parent-title '{account_id}'
"""

from __future__ import annotations

import argparse
import mimetypes
import os
import re
import ssl
import sys
import textwrap
from datetime import date
from pathlib import Path
from typing import Any

import html as html_mod
from html.parser import HTMLParser

try:
    import certifi
    import requests
    from requests.adapters import HTTPAdapter
    from requests.auth import HTTPBasicAuth
except ImportError:  # pragma: no cover
    sys.exit("Missing dependency: pip install requests")

try:
    import markdown as markdown_lib
except ImportError:  # pragma: no cover
    sys.exit("Missing dependency: pip install markdown")


# --------------------------------------------------------------------------- #
# Configuration - edit here, or override any of it with CLI flags / env vars
# --------------------------------------------------------------------------- #

# <<< PLACEHOLDER: put your real Confluence Cloud base URL here >>>
# Shape: https://<your-domain>.atlassian.net/wiki
DEFAULT_BASE_URL = os.environ.get("CONFLUENCE_BASE_URL", "https://YOUR-DOMAIN.atlassian.net/wiki")

DEFAULT_SPACE_KEY = os.environ.get("CONFLUENCE_SPACE", "YOURSPACE")

# Parent page for the whole run - the page every document is created under.
# Supports {account_id}, so "{account_id}" nests everything under the page you
# created manually for that account. Empty = top level of the space.
DEFAULT_PARENT_TITLE = os.environ.get("CONFLUENCE_PARENT", "{account_id}")

# CA bundle used to verify the TLS connection - set this to your corporate root
# CA if your network inspects TLS traffic. Empty = the public roots only.
# $REQUESTS_CA_BUNDLE and --ca-bundle override it. "~" is expanded.
DEFAULT_CA_BUNDLE = os.environ.get("REQUESTS_CA_BUNDLE", "confluence.crt")

# Confluence Cloud authenticates with your account email + an API token: the
# token acts as the password for that account, so both are needed.
TOKEN_ENV = "CONFLUENCE_API_TOKEN"
USER_ENV = "CONFLUENCE_USER"

# file name (without extension) -> Confluence page title.
#
# {account_id} in a key matches the account id inside the file name; in a title
# it is replaced with the account id of this run. Other placeholders available
# in titles: {filename}, {stem}, {date}.
#
# Entries are checked top to bottom, first match wins.
PAGE_MAP: dict[str, str] = {
    "01_scp_analysis":                    "[{account_id}] SCP Analysis",
    "02_ecr_{account_id}_analysis":       "[{account_id}] ECR Analysis",
    "03_iam_{account_id}_access_review":  "[{account_id}] IAM Access Review",
}


# --------------------------------------------------------------------------- #
# File name -> page title
# --------------------------------------------------------------------------- #

# Extensions treated as page content; anything else can only be an attachment.
PAGE_EXTS = {".md", ".markdown", ".html", ".htm", ".xhtml", ".txt"}

def compile_pattern(pattern: str, account_id: str) -> re.Pattern:
    r"""Turn a plain file-name pattern into an anchored regex.

    "02_ecr_{account_id}_analysis" with --account-id 023414512345
        -> ^02_ecr_(?P<account_id>023414512345)_analysis$
    "02_ecr_{account_id}_analysis" without one
        -> ^02_ecr_(?P<account_id>\d{6,14})_analysis$
    "re:..." is used as a raw regex, in case a file name ever needs one.
    """
    if pattern.startswith("re:"):
        return re.compile(pattern[3:], re.IGNORECASE)
    account_re = re.escape(account_id) if account_id else r"\d{6,14}"
    parts = []
    for token in re.split(r"(\{account_id\}|\*)", pattern):
        if token == "{account_id}":
            parts.append(f"(?P<account_id>{account_re})")
        elif token == "*":
            parts.append(".*")
        elif token:
            parts.append(re.escape(token))
    return re.compile("".join(parts) + r"\Z", re.IGNORECASE)


class _SafeDict(dict):
    def __missing__(self, key: str) -> str:
        raise KeyError(key)


def render(template: str, placeholders: dict[str, str], what: str) -> str:
    try:
        return template.format_map(_SafeDict(placeholders)).strip()
    except KeyError as exc:
        if exc.args[0] == "account_id":
            raise SystemExit(f"{what} {template!r} uses {{account_id}}, but no account id is known. "
                             f"Pass --account-id.")
        raise SystemExit(f"{what} {template!r} uses unknown placeholder {exc}. "
                         f"Available: {', '.join(sorted(placeholders))}")


def normalize_keys(page_map: dict[str, str], match_full_name: bool) -> dict[str, str]:
    """Keys are matched against the file name without its extension.

    Writing "01_scp_analysis.md" instead of "01_scp_analysis" is a natural
    mistake, so drop a document extension from the key rather than never
    matching it. Skipped when --match-full-name asks for the opposite.
    """
    if match_full_name:
        return page_map
    out = {}
    for key, title in page_map.items():
        stem = key[: -len(suffix)] if (suffix := Path(key).suffix.lower()) in PAGE_EXTS else key
        out[stem] = title
    return out


def resolve_title(path: Path, page_map: dict[str, str], account_id: str,
                  match_full_name: bool) -> str | None:
    """Find the first mapping entry matching this file and render its title."""
    subject = path.name if match_full_name else path.stem
    for pattern, title in page_map.items():
        match = compile_pattern(pattern, account_id).match(subject)
        if not match:
            continue
        placeholders = {
            "filename": path.name,
            "stem": path.stem,
            "date": date.today().isoformat(),
        }
        # from the file name if captured there, otherwise from --account-id;
        # left out entirely when unknown, so rendering fails loudly
        found_account = match.groupdict().get("account_id") or account_id
        if found_account:
            placeholders["account_id"] = found_account
        return render(title, placeholders, f"[{path.name}] title")
    return None


# --------------------------------------------------------------------------- #
# Markdown -> Confluence storage format
# --------------------------------------------------------------------------- #

# Extensions covering everything GitHub-flavoured Markdown users expect to work:
# tables, fenced code, footnotes, definition lists, attribute lists, abbreviations,
# correct nesting of sub-lists, and Markdown inside raw HTML blocks.
MD_EXTENSIONS = ["extra", "sane_lists", "admonition"]


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _code_macro(language: str, code: str) -> str:
    """Confluence code macro - syntax highlighting and a copy button, like a fenced block."""
    lang = (language or "text").strip() or "text"
    return (
        '<ac:structured-macro ac:name="code" ac:schema-version="1">'
        f'<ac:parameter ac:name="language">{_escape(lang)}</ac:parameter>'
        f"<ac:plain-text-body><![CDATA[{code.replace(']]>', ']]]]><![CDATA[>')}]]></ac:plain-text-body>"
        "</ac:structured-macro>"
    )


LIST_MARKER = re.compile(r"^(\s*)([-*+]|\d+[.)])\s+")
FENCE = re.compile(r"^\s*```")


def normalize_list_indent(text: str) -> str:
    """Rescale 2- and 3-space list nesting to the 4 spaces python-markdown needs.

    Most editors and generators nest sub-lists by two spaces, which would
    otherwise be flattened into one long list instead of a nested one.
    """
    lines = text.split("\n")
    out = list(lines)
    i = 0
    while i < len(lines):
        start = LIST_MARKER.match(lines[i])
        if not start or start.group(1):  # only blocks starting at column 0
            i += 1
            continue

        # find the extent of this list block and the indents used inside it
        j, indents, in_fence = i, set(), False
        while j < len(lines):
            line = lines[j]
            if FENCE.match(line):
                in_fence = not in_fence
            elif not in_fence:
                if not line.strip():  # a blank line ends the list unless indented text follows
                    k = j + 1
                    while k < len(lines) and not lines[k].strip():
                        k += 1
                    if k >= len(lines) or not (LIST_MARKER.match(lines[k]) or lines[k][:1].isspace()):
                        break
                    j = k
                    continue
                marker = LIST_MARKER.match(line)
                if marker:
                    indents.add(len(marker.group(1).expandtabs(4)))
                elif not line[:1].isspace():  # plain paragraph at column 0
                    break
            j += 1

        # map the indents actually used onto 0, 4, 8, ... so every level nests
        levels = sorted(indents)
        mapping = {indent: 4 * rank for rank, indent in enumerate(levels)}
        last_marker, shift, in_fence = 0, 0, False
        for k in range(i, j):
            stripped = lines[k].lstrip()
            if not stripped:
                continue
            indent = len(lines[k].expandtabs(4)) - len(stripped)
            if in_fence:  # keep the block's inner indentation, just move it with its fence
                out[k] = " " * max(0, indent + shift) + stripped
                if FENCE.match(lines[k]):
                    in_fence = False
                continue
            if LIST_MARKER.match(lines[k]):
                last_marker = indent
                new_indent = mapping.get(indent, indent)
            elif indent:
                # continuation of the item above: one level in, keeping any extra depth
                base = mapping.get(last_marker, last_marker)
                new_indent = base + 4 + max(0, indent - last_marker - 4)
            else:
                new_indent = 0
            if FENCE.match(lines[k]):
                in_fence, shift = True, new_indent - indent
            out[k] = " " * new_indent + stripped
        i = max(j, i + 1)
    return "\n".join(out)


def convert_task_lists(fragment: str) -> str:
    """"- [ ] item" lists become real Confluence checkboxes instead of literal brackets."""
    def convert(m: re.Match) -> str:
        items = re.findall(r"<li>(.*?)</li>", m.group(1), flags=re.DOTALL)
        if not items or not all(re.match(r"\[[ xX]\]\s", i.strip()) for i in items):
            return m.group(0)
        tasks = []
        for index, item in enumerate(items, start=1):
            done = item.strip()[1].lower() == "x"
            body = item.strip()[3:].strip()
            tasks.append(f"<ac:task><ac:task-id>{index}</ac:task-id>"
                         f"<ac:task-status>{'complete' if done else 'incomplete'}</ac:task-status>"
                         f"<ac:task-body>{body}</ac:task-body></ac:task>")
        return f"<ac:task-list>{''.join(tasks)}</ac:task-list>"

    return re.sub(r"<ul>(.*?)</ul>", convert, fragment, flags=re.DOTALL)


FENCE_OPEN = re.compile(r"^(\s*)(`{3,}|~{3,})\s*([\w+#.-]*)\s*$")
CODE_TOKEN = "xconfluencecodeblock{}x"


def extract_fenced_blocks(text: str) -> tuple[str, list[tuple[str, str]]]:
    """Pull fenced code blocks out before conversion, leaving a placeholder line.

    Markdown converters do not recognise a fenced block nested inside a list
    item; handling the fences here makes them work anywhere, at any indentation.
    """
    lines = text.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    blocks: list[tuple[str, str]] = []
    i = 0
    while i < len(lines):
        opening = FENCE_OPEN.match(lines[i])
        if not opening:
            out.append(lines[i])
            i += 1
            continue
        indent, marker, language = opening.group(1), opening.group(2)[0], opening.group(3)
        closing = re.compile(rf"^\s*{re.escape(marker)}{{3,}}\s*$")
        body, i = [], i + 1
        while i < len(lines) and not closing.match(lines[i]):
            body.append(lines[i])
            i += 1
        i += 1  # skip the closing fence
        # keep the placeholder a block of its own, so the text after it is not
        # swallowed as a lazy continuation of the same paragraph
        if out and out[-1].strip():
            out.append("")
        out.append(indent + CODE_TOKEN.format(len(blocks)))
        out.append("")
        blocks.append((language, textwrap.dedent("\n".join(body)).strip("\n")))
    return "\n".join(out), blocks


def restore_fenced_blocks(fragment: str, blocks: list[tuple[str, str]]) -> str:
    for index, (language, code) in enumerate(blocks):
        token = CODE_TOKEN.format(index)
        macro = _code_macro(language, code)
        fragment = re.sub(rf"<p>\s*{token}\s*</p>", lambda m, v=macro: v, fragment)
        fragment = fragment.replace(token, macro)
    return fragment


def markdown_to_html(text: str) -> str:
    # ~~strikethrough~~ is GFM, not core Markdown; raw HTML passes through untouched
    text = re.sub(r"~~(.+?)~~", r"<del>\1</del>", text, flags=re.DOTALL)
    text = normalize_list_indent(text)
    return markdown_lib.markdown(text, extensions=MD_EXTENSIONS, output_format="xhtml")


# Storage format is XML, so the body must be well-formed: every tag closed, every
# unknown tag gone. Markdown lets raw HTML through, and prose like "<not-a-tag>"
# or a stray </div> would otherwise make Confluence reject the whole page.
ALLOWED_TAGS = {
    "p", "br", "hr", "h1", "h2", "h3", "h4", "h5", "h6", "strong", "em", "b", "i",
    "u", "del", "s", "code", "pre", "blockquote", "ul", "ol", "li", "table", "thead",
    "tbody", "tfoot", "tr", "th", "td", "caption", "a", "img", "sup", "sub", "span",
    "div", "dl", "dt", "dd", "hr",
}
VOID_TAGS = {"br", "hr", "img"}
ALLOWED_ATTRS = {"href", "src", "alt", "title", "class", "id", "colspan", "rowspan", "align"}


class _XhtmlSanitizer(HTMLParser):
    """Rewrite an HTML fragment as well-formed XHTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.stack: list[str] = []

    def _keep(self, tag: str) -> bool:
        return tag in ALLOWED_TAGS or tag.startswith(("ac:", "ri:"))

    def _attrs(self, attrs: list[tuple[str, str | None]]) -> str:
        kept = []
        for name, value in attrs:
            if name in ALLOWED_ATTRS or name.startswith(("ac:", "ri:")):
                kept.append(f' {name}="{_escape(value or "")}"')
        return "".join(kept)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if not self._keep(tag):
            return
        if tag in VOID_TAGS:
            self.out.append(f"<{tag}{self._attrs(attrs)} />")
        else:
            self.stack.append(tag)
            self.out.append(f"<{tag}{self._attrs(attrs)}>")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self._keep(tag):
            self.out.append(f"<{tag}{self._attrs(attrs)} />")

    def handle_endtag(self, tag: str) -> None:
        if not self._keep(tag) or tag in VOID_TAGS or tag not in self.stack:
            return  # unknown or stray closing tag
        while self.stack:  # also closes anything left open inside it
            open_tag = self.stack.pop()
            self.out.append(f"</{open_tag}>")
            if open_tag == tag:
                break

    def handle_data(self, data: str) -> None:
        self.out.append(_escape(data))

    def result(self) -> str:
        while self.stack:
            self.out.append(f"</{self.stack.pop()}>")
        return "".join(self.out)


def sanitize_xhtml(fragment: str) -> str:
    parser = _XhtmlSanitizer()
    parser.feed(fragment)
    parser.close()
    return parser.result()


def _convert_images(fragment: str, base_dir: Path) -> tuple[str, list[Path]]:
    """<img> is not storage format. Local images become attachments, remote ones ri:url."""
    attachments: list[Path] = []

    def repl(m: re.Match) -> str:
        attrs = m.group(1)
        src = (re.search(r'src="([^"]*)"', attrs) or [None, ""])[1]
        alt = (re.search(r'alt="([^"]*)"', attrs) or [None, ""])[1]
        alt_attr = f' ac:alt="{alt}"' if alt else ""
        if not src:
            return ""
        if re.match(r"^(https?:)?//", src) or src.startswith("data:"):
            return f'<ac:image{alt_attr}><ri:url ri:value="{src}" /></ac:image>'
        local = (base_dir / html_mod.unescape(src)).resolve()
        if not local.is_file():
            print(f"       note: image {src!r} not found next to the document, skipping it")
            return ""
        attachments.append(local)
        return f'<ac:image{alt_attr}><ri:attachment ri:filename="{local.name}" /></ac:image>'

    return re.sub(r"<img([^>]*?)/?>", repl, fragment), attachments


def html_to_storage(fragment: str, base_dir: Path, blocks: list[tuple[str, str]] | None = None
                    ) -> tuple[str, list[Path]]:
    """XHTML -> Confluence storage format. Returns the body and any images to attach."""
    macros: list[str] = []

    def stash_code(m: re.Match) -> str:
        language = re.sub(r"^(language-|lang-)", "", (m.group(1) or "").strip())
        macros.append(_code_macro(language, html_mod.unescape(m.group(2))))
        return f"\x00MACRO{len(macros) - 1}\x00"

    fragment = convert_task_lists(sanitize_xhtml(fragment))
    fragment = re.sub(r'<pre><code(?:\s+class="([^"]*)")?>(.*?)</code></pre>',
                      stash_code, fragment, flags=re.DOTALL)
    fragment, images = _convert_images(fragment, base_dir)
    fragment = re.sub(r"\x00MACRO(\d+)\x00", lambda m: macros[int(m.group(1))], fragment)
    fragment = restore_fenced_blocks(fragment, blocks or [])
    return fragment, images


def file_to_storage(path: Path) -> tuple[str, list[Path]]:
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in {".html", ".htm", ".xhtml"}:
        return html_to_storage(text, path.parent)
    if suffix in {".md", ".markdown"}:
        text, blocks = extract_fenced_blocks(text)
        return html_to_storage(markdown_to_html(text), path.parent, blocks)
    return _code_macro("text", text), []  # plain text keeps its formatting


# --------------------------------------------------------------------------- #
# Confluence Cloud REST client
# --------------------------------------------------------------------------- #

class _ExtraCAAdapter(HTTPAdapter):
    """Trusts an extra CA bundle *in addition to* the public roots.

    Plain `verify=<file>` would replace them, which breaks every request made
    from outside the network that needs the corporate CA.
    """

    def __init__(self, ca_bundle: str, **kwargs: Any) -> None:
        self._ca_bundle = ca_bundle
        super().__init__(**kwargs)

    def init_poolmanager(self, *args: Any, **kwargs: Any) -> Any:
        context = ssl.create_default_context(cafile=certifi.where())
        context.load_verify_locations(cafile=self._ca_bundle)
        kwargs["ssl_context"] = context
        return super().init_poolmanager(*args, **kwargs)


class _Session(requests.Session):
    """A session that turns TLS failures into an explanation instead of a traceback."""

    def request(self, *args: Any, **kwargs: Any) -> requests.Response:
        try:
            return super().request(*args, **kwargs)
        except requests.exceptions.SSLError as exc:
            raise SystemExit(
                f"TLS verification failed: {exc}\n\n"
                "If your network inspects TLS traffic, point --ca-bundle at your company root CA "
                "certificate, or set DEFAULT_CA_BUNDLE in this script."
            ) from exc


class Confluence:
    def __init__(self, base_url: str, token: str, user: str | None, timeout: int = 30,
                 ca_bundle: str | None = None):
        if not user:
            raise SystemExit(f"Missing ${USER_ENV} - Confluence Cloud needs your account email next "
                             f"to the token. Export it or pass --user.")
        self.base = base_url.rstrip("/")
        self.api = f"{self.base}/rest/api"
        self.timeout = timeout
        self.s = _Session()
        self.s.auth = HTTPBasicAuth(user, token)
        self.s.headers["Accept"] = "application/json"
        if ca_bundle:
            self.s.mount("https://", _ExtraCAAdapter(ca_bundle))

    def _check(self, r: requests.Response) -> Any:
        if not r.ok:
            raise SystemExit(f"Confluence API {r.status_code} {r.request.method} {r.request.url}\n{r.text[:2000]}")
        return r.json() if r.content else {}

    def find_page(self, space: str, title: str) -> dict | None:
        r = self.s.get(
            f"{self.api}/content",
            params={"spaceKey": space, "title": title, "expand": "version", "limit": 1},
            timeout=self.timeout,
        )
        results = self._check(r).get("results", [])
        return results[0] if results else None

    def create_page(self, space: str, title: str, storage: str, parent_id: str | None) -> dict:
        payload: dict[str, Any] = {
            "type": "page",
            "title": title,
            "space": {"key": space},
            "body": {"storage": {"value": storage, "representation": "storage"}},
        }
        if parent_id:
            payload["ancestors"] = [{"id": str(parent_id)}]
        return self._check(self.s.post(f"{self.api}/content", json=payload, timeout=self.timeout))

    def update_page(self, page: dict, space: str, title: str, storage: str,
                    parent_id: str | None, message: str) -> dict:
        payload: dict[str, Any] = {
            "id": page["id"],
            "type": "page",
            "title": title,
            "space": {"key": space},
            "body": {"storage": {"value": storage, "representation": "storage"}},
            "version": {"number": page["version"]["number"] + 1, "message": message, "minorEdit": False},
        }
        if parent_id:
            payload["ancestors"] = [{"id": str(parent_id)}]
        return self._check(self.s.put(f"{self.api}/content/{page['id']}", json=payload, timeout=self.timeout))

    def upload_attachment(self, page_id: str, path: Path) -> dict:
        """Create or replace an attachment on a page."""
        ctype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        existing = self._check(self.s.get(
            f"{self.api}/content/{page_id}/child/attachment",
            params={"filename": path.name, "limit": 1}, timeout=self.timeout,
        )).get("results", [])
        url = f"{self.api}/content/{page_id}/child/attachment"
        if existing:
            url = f"{url}/{existing[0]['id']}/data"
        with path.open("rb") as fh:
            files = {"file": (path.name, fh, ctype), "comment": (None, "uploaded by confluence_upload.py")}
            return self._check(self.s.post(url, files=files, headers={"X-Atlassian-Token": "no-check"},
                                           timeout=self.timeout * 4))

    def page_url(self, page: dict) -> str:
        webui = page.get("_links", {}).get("webui")
        return f"{self.base}{webui}" if webui else self.base


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def collect_files(args: argparse.Namespace) -> list[Path]:
    files: list[Path] = [Path(f) for f in args.files]
    if args.path:
        root = Path(args.path).expanduser()
        if root.is_file():
            files.append(root)
        elif root.is_dir():
            it = root.rglob(args.glob) if args.recursive else root.glob(args.glob)
            files += sorted(p for p in it if p.is_file())
        else:
            raise SystemExit(f"--path {root} does not exist.")
    missing = [f for f in files if not f.is_file()]
    if missing:
        raise SystemExit("Not a file: " + ", ".join(str(m) for m in missing))
    if not files:
        raise SystemExit(f"No input files. Use --path <dir-with-md-files> (glob {args.glob!r}) "
                         f"or pass file paths explicitly.")
    seen, unique = set(), []
    for f in files:  # de-duplicate, keep order
        rp = f.resolve()
        if rp not in seen:
            seen.add(rp)
            unique.append(f)
    return unique


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Upload documents to Confluence using a file name -> page title mapping.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("files", nargs="*", help="additional explicit file paths to upload")
    p.add_argument("-p", "--path", "--dir", dest="path", default=os.environ.get("CONFLUENCE_DOCS_DIR"),
                   help="local path with the documents: a directory to scan, or a single file "
                        "(or $CONFLUENCE_DOCS_DIR)")
    p.add_argument("--glob", default="*.md", help="glob used when --path is a directory (default: *.md)")
    p.add_argument("--recursive", action="store_true", help="scan --path recursively")

    p.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"Confluence base URL (default: {DEFAULT_BASE_URL})")
    p.add_argument("--space", default=DEFAULT_SPACE_KEY, help="target space key")
    p.add_argument("--account-id",
                   help="REQUIRED: AWS account id for this run, used in file matching "
                        "and as {account_id} in titles and in --parent-title")
    parent = p.add_mutually_exclusive_group()
    parent.add_argument("--parent-title", default=DEFAULT_PARENT_TITLE,
                        help="title of the page everything is created under; supports {account_id}")
    parent.add_argument("--parent-id", help="parent page id, if you prefer the id over the title")
    p.add_argument("--create-missing-parents", action="store_true",
                   help="create the parent page if it does not exist yet")

    p.add_argument("--match-full-name", action="store_true", help="match keys against the file name with extension")
    p.add_argument("--strict", action="store_true", help="fail instead of skipping when a file matches nothing")
    p.add_argument("--attachments", action="store_true",
                   help="upload non-document files (pdf, png, csv...) as attachments to their mapped page")
    p.add_argument("--lookup", metavar="TITLE", help="print the page id + URL for TITLE in --space and exit")
    p.add_argument("--user", default=os.environ.get(USER_ENV),
                   help=f"Atlassian account email (or ${USER_ENV})")
    p.add_argument("--ca-bundle", default=DEFAULT_CA_BUNDLE,
                   help="CA certificate bundle to trust, e.g. your company root CA "
                        "(default: DEFAULT_CA_BUNDLE / $REQUESTS_CA_BUNDLE)")
    p.add_argument("--version-message", default="Automated upload via confluence_upload.py")
    p.add_argument("--dry-run", action="store_true", help="print planned actions, make no API calls")
    args = p.parse_args(argv)

    if not args.account_id and not args.lookup:
        raise SystemExit("--account-id is required: it selects which reports to pick up and "
                         "fills {account_id} in page titles.")

    page_map = normalize_keys(PAGE_MAP, args.match_full_name)
    if not page_map:
        raise SystemExit("PAGE_MAP is empty - nothing to match file names against.")

    files = [] if args.lookup else collect_files(args)

    token = os.environ.get(TOKEN_ENV, "")
    if not token and not args.dry_run:
        raise SystemExit(f"Missing ${TOKEN_ENV}. Export your Confluence API token first.")
    if "YOUR-DOMAIN" in args.base_url and not args.dry_run:
        raise SystemExit("Set a real --base-url (or $CONFLUENCE_BASE_URL) - the placeholder is still in place.")

    ca_bundle = str(Path(args.ca_bundle).expanduser()) if args.ca_bundle else None
    if ca_bundle and not Path(ca_bundle).is_file():
        raise SystemExit(f"CA bundle {ca_bundle} does not exist. Fix DEFAULT_CA_BUNDLE in this "
                         f"script, $REQUESTS_CA_BUNDLE, or --ca-bundle.")

    api = None if args.dry_run else Confluence(args.base_url, token, args.user, ca_bundle=ca_bundle)

    if args.lookup:
        if not api:
            raise SystemExit("--lookup needs a real API call, drop --dry-run.")
        found = api.find_page(args.space, args.lookup)
        if not found:
            raise SystemExit(f"Page {args.lookup!r} not found in space {args.space}.")
        print(f"id={found['id']}  {api.page_url(found)}")
        return 0

    # Parent page: one per run, resolved once.
    parent_title = render(args.parent_title or "",
                          {"account_id": args.account_id} if args.account_id else {},
                          "--parent-title")
    parent_id = args.parent_id
    if not parent_id and parent_title and api:
        found = api.find_page(args.space, parent_title)
        if not found:
            if not args.create_missing_parents:
                raise SystemExit(f"Parent page {parent_title!r} not found in space {args.space}. "
                                 f"Create it in Confluence first, or pass --create-missing-parents.")
            found = api.create_page(args.space, parent_title, f"<p>{_escape(parent_title)}</p>", None)
            print(f"CREATE     parent page {parent_title!r}  {api.page_url(found)}")
        parent_id = found["id"]

    ok = skipped = failed = 0
    for path in files:
        title = resolve_title(path, page_map, args.account_id, args.match_full_name)
        if not title:
            msg = f"SKIP   {path.name}: no entry in the mapping matches this file name"
            if args.strict:
                raise SystemExit(msg)
            print(msg)
            skipped += 1
            continue

        is_page = path.suffix.lower() in PAGE_EXTS
        if not is_page and not args.attachments:
            print(f"SKIP   {path.name}: not a document (use --attachments to upload it as an attachment)")
            skipped += 1
            continue

        if args.dry_run:
            where = parent_id or (f"{parent_title!r} (resolved at upload time)" if parent_title else "space root")
            print(f"DRY    {path.name} -> [{args.space}] {title!r} "
                  f"({'page' if is_page else 'attachment'}, parent={where})")
            ok += 1
            continue

        try:
            existing = api.find_page(args.space, title)
            if is_page:
                storage, images = file_to_storage(path)
                if existing:
                    page = api.update_page(existing, args.space, title, storage, parent_id, args.version_message)
                    action = f"UPDATE v{page['version']['number']}"
                else:
                    page = api.create_page(args.space, title, storage, parent_id)
                    action = "CREATE"
                for image in images:  # referenced by the page body, so upload them too
                    api.upload_attachment(page["id"], image)
            else:
                images = []
                page = existing or api.create_page(
                    args.space, title, f"<p>Attachments for {_escape(path.stem)}.</p>", parent_id)
                api.upload_attachment(page["id"], path)
                action = "ATTACH"

            print(f"{action:<10} {path.name} -> {title!r}  {api.page_url(page)}")
            ok += 1
        except SystemExit as exc:
            print(f"FAIL   {path.name}: {exc}", file=sys.stderr)
            failed += 1

    print(f"\nDone: {ok} ok, {skipped} skipped, {failed} failed.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
