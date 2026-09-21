# confluence-uploader

Upload local Markdown documents to Confluence Cloud as pages, driven by a simple
`file name -> page title` mapping. Re-running updates the existing pages instead
of creating duplicates, so it is safe to wire into a report-generation job.

One run targets one place: a space, a parent page, and one AWS account — the
account id is passed per run with `--account-id`, since it differs every time.
The only thing that varies per file is the page title.

## Requirements

```bash
pip install -r requirements.txt   # requests + markdown
```

Python 3.10+.

## Setup

```bash
export CONFLUENCE_BASE_URL='https://your-domain.atlassian.net/wiki'
export CONFLUENCE_USER='you@example.com'     # your Atlassian account email
export CONFLUENCE_API_TOKEN='...'            # API token, not your password
```

| Variable | Purpose |
| --- | --- |
| `CONFLUENCE_API_TOKEN` | Atlassian API token. Required. |
| `CONFLUENCE_USER` | Atlassian account email. Required. |
| `CONFLUENCE_BASE_URL` | Base URL. Also settable with `--base-url` or in `DEFAULT_BASE_URL`. |
| `CONFLUENCE_SPACE` | Default space key, overridable with `--space`. |
| `CONFLUENCE_PARENT` | Default parent page title, overridable with `--parent-title`. |
| `CONFLUENCE_DOCS_DIR` | Default document directory, overridable with `--path`. |

Create an API token at <https://id.atlassian.com/manage-profile/security/api-tokens>.

Confluence Cloud has no token-only authentication: the API token acts as the
password for your account, so the request also needs the account email in
`$CONFLUENCE_USER` (or `--user`).

## Usage

```bash
# see what would happen - no API calls at all
python3 confluence_upload.py -p ./reports --space CLOUD --account-id 023414512345 --dry-run

# upload every *.md from a directory
python3 confluence_upload.py -p ./reports --space CLOUD --account-id 023414512345

# recursive scan of a tree of report directories
python3 confluence_upload.py -p ~/work/audits -r --space CLOUD --account-id 023414512345

# a single file
python3 confluence_upload.py -p ./reports/01_scp_analysis.md --space CLOUD --account-id 023414512345

# look up a page id by title
python3 confluence_upload.py --lookup '023414512345' --space CLOUD
```

Always start with `--dry-run`. It resolves the mapping and prints the target
title, space and parent for every file without touching Confluence.

## The mapping

`PAGE_MAP` at the top of the script maps a literal file name to a page title.
Write the name **without the extension** — `01_scp_analysis` matches
`01_scp_analysis.md`. (A trailing `.md` in a key is stripped rather than left to
never match, so both spellings work.)

```python
PAGE_MAP = {
    "01_scp_analysis":                    "[{account_id}] SCP Analysis",
    "02_ecr_{account_id}_analysis":       "[{account_id}] ECR Analysis",
    "03_iam_{account_id}_access_review":  "[{account_id}] IAM Access Review",
}
```

With `--account-id 023414512345`, `02_ecr_023414512345_analysis.md` becomes the
page **`[023414512345] ECR Analysis`**.

`{account_id}` is the only wildcard you normally need:

- **in a key** it matches the account id embedded in the file name. With
  `--account-id` set it matches that exact id, so reports belonging to another
  account are skipped rather than silently uploaded to the wrong place. Without
  it, any 6-14 digit number matches.
- **in a title** it is replaced with the account id of this run (or the one
  captured from the file name). If no account id is known, the run stops with an
  error instead of producing a page called `[] ECR Analysis`.

Titles also accept `{filename}`, `{stem}` and `{date}`. A `*` in a key matches
anything without capturing it, and a key starting with `re:` is treated as a raw
regex — neither is needed for plain, predictable file names.

Entries are checked top to bottom and the first match wins. Files matching
nothing are skipped with a message; `--strict` turns that into an error.

`--match-full-name` switches matching to the full file name including the
extension — only useful when two files share a stem, e.g. `report.md` and
`report.html`. Keys must then spell the extension out.

## Where the pages land

The destination is global for the run, not part of the mapping:

- `--space CLOUD` — the space key.
- `--parent-title '{account_id}'` — the page everything is created under, looked
  up by title in that space. This is the default: create a page titled with the
  account id manually, and every document lands beneath it. Any fixed title
  (`--parent-title 'AWS Audits'`) works too; an empty value means the space root.
- `--parent-id 3512761234` — use this instead if you prefer an id over a title.

You never need a URL. If the parent page does not exist the run stops with a
clear message; `--create-missing-parents` creates it instead. To get a raw page
id, take the number after `/pages/` in the page URL
(`.../wiki/spaces/CLOUD/pages/3512761234/My+Page`) or run `--lookup 'My Page'`.

## Markdown rendering

Documents are converted to Confluence storage format, so a page looks like the
rendered `.md`, not like a pasted text file:

| Markdown | In Confluence |
| --- | --- |
| headings, paragraphs, `**bold**`, `*italic*`, `~~strikethrough~~`, `` `code` `` | native formatting |
| tables, including alignment | native tables |
| bullet and numbered lists, nested to any depth | native nested lists |
| fenced code blocks, anywhere — including inside list items | code macro with syntax highlighting and a copy button |
| `- [ ]` / `- [x]` lists | real Confluence checkboxes (task lists) |
| block quotes, horizontal rules, links | native equivalents |
| definition lists, footnotes, abbreviations | native HTML equivalents |
| `![alt](diagram.png)` | the image file is uploaded as a page attachment and embedded |
| `![alt](https://…/logo.png)` | embedded from the URL |

Details worth knowing:

- **List indentation.** Sub-lists nested by 2 or 3 spaces are normalised to the
  4 spaces the converter needs, so a list written the GitHub way nests correctly
  rather than flattening into one level.
- **Well-formedness.** Storage format is XML, and Confluence rejects a whole page
  if the body is malformed. The output is run through a sanitizer that closes
  every tag, drops stray ones, and escapes prose that merely looks like a tag
  (`<not-a-tag>`, `AT&T`), so a report cannot fail the upload over punctuation.
- **Raw HTML** in a Markdown file is passed through when it uses standard tags,
  and escaped to visible text otherwise.

## Behaviour notes

- **Create vs update.** A page is matched by exact title within the space. If it
  exists it is updated and its version is bumped; otherwise it is created. Page
  titles are unique per space in Confluence, which is why prefixing them with the
  account id matters when several accounts produce the same report.
- **Supported inputs.** `.md`, `.markdown`, `.html`, `.htm`, `.xhtml`, `.txt`.
  Plain text is wrapped in a code block. See [Markdown rendering](#markdown-rendering).
- **Attachments.** With `--attachments`, files that are not documents (PNG, PDF,
  CSV, …) are uploaded as attachments to their mapped page, replacing an
  attachment of the same name. Without the flag they are skipped.
- **Exit code.** `0` when nothing failed, `1` otherwise. Skipped files are not
  failures.

## TLS behind a corporate proxy

If the upload fails with `SSL: CERTIFICATE_VERIFY_FAILED`, your network is most
likely inspecting TLS traffic and presenting its own CA. Two flags cover it:

```bash
# 1. trust your company root CA
python3 confluence_upload.py ... --ca-bundle /path/to/corporate-root-ca.pem
#    equivalent: export REQUESTS_CA_BUNDLE=/path/to/corporate-root-ca.pem

# 2. if the error mentions a strict check, e.g.
#    "basic constraints of CA cert not marked critical"
python3 confluence_upload.py ... --relaxed-tls
```

`--relaxed-tls` is needed because Python 3.13 turned on `VERIFY_X509_STRICT` by
default, and many inspection-proxy CAs are not strictly RFC 5280 compliant. It
drops only that strictness check — the certificate chain, hostname and expiry are
still verified, so a self-signed or mismatched certificate is still rejected.
There is no option to disable verification altogether.

On macOS the company root CA can usually be exported from Keychain Access, or
dumped with:

```bash
security find-certificate -a -p /Library/Keychains/System.keychain > corporate-ca.pem
```

## Options

```
-p, --path PATH           directory to scan or a single file (or $CONFLUENCE_DOCS_DIR)
    --glob GLOB           glob used when --path is a directory (default: *.md)
    --recursive           scan --path recursively
    --base-url URL        Confluence base URL
    --space KEY           target space key
    --account-id ID       AWS account id for this run (required)
    --parent-title TITLE  parent page title, supports {account_id}
    --parent-id ID        parent page id, instead of the title
    --create-missing-parents  create the parent page when it does not exist
    --match-full-name     match keys against the file name including its extension
    --strict              fail instead of skipping when a file matches nothing
    --attachments         upload non-document files as attachments
    --lookup TITLE        print the page id + URL for TITLE and exit
    --user EMAIL          Atlassian account email (or $CONFLUENCE_USER)
    --ca-bundle FILE      CA bundle to trust (or $REQUESTS_CA_BUNDLE)
    --relaxed-tls         skip strict RFC 5280 checks, keep verification
    --version-message MSG version comment recorded on updates
    --dry-run             print planned actions, make no API calls
```
