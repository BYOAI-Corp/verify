# How to check a BYOAI or Sworn receipt

A receipt is a small file that records a piece of work, such as a verified document or the steps of an
investigation, and is signed with a key. Checking it tells you two things: **nothing in it has been
changed since it was signed**, and **which key signed it**. You do not need to trust BYOAI to do this:
the checker is open source and runs on your own computer.

## The quick way: the web checker

**Quickest:** open https://byoai-corp.github.io/verify/ and go to step 3. This is the same checker
as the release download, hosted on GitHub Pages. It is not allowed to use the network once loaded:
nothing you check leaves your computer. It is for convenience only. The hosted page is not covered by
the release seal, so it can only be checked after it has run. For a receipt you rely on as evidence,
use the download in steps 1 and 2 and check it as described under "Checking the checker".

1. Open the [latest release](https://github.com/BYOAI-Corp/verify/releases/latest) and download
   `byoai-receipt-checker_v0_1_0.html`.
2. Open that file in any web browser (Chrome, Edge, Firefox or Safari). It works with no internet
   connection, and it is not allowed to use the network: nothing you check leaves your computer.
3. Drop the receipt file onto the page, or choose it.
4. Enter the public key of whoever signed it. This is a 64-character code that they publish. For
   receipts BYOAI signed, press **Use BYOAI's release key**. BYOAI's key is
   `bb1de39b94a44708e3abf583a9689fa3658e247ff7dbd96703f0c216ab8e7154`, also published at
   [github.com/BYOAI-Corp](https://github.com/BYOAI-Corp).
5. For a **case handoff receipt**, you can also choose the folder of source files that came with it.
   The checker then confirms each source is exactly the file the receipt names. Choose the folder,
   not single files: with single files the checker can match them only by file name.
6. Press **Check the receipt**.

## What the result means

| Result | Meaning |
|---|---|
| **VERIFIED** | Signed receipts only (case handoffs, Verified Declaration receipts, release seals): not changed since it was signed, nothing missing, and signed by the key you entered. For a case handoff with source files, every source matched. |
| **VERIFIED — signature and chain only** | A case handoff checked without its source files. The record is intact, but the sources themselves were not compared. |
| **CHAIN INTACT — NOT SIGNED** | Ticket ledgers, call logs, gate logs and custody exports carry no signature. This only means their rows fit together: anyone can build a chain like this. Rely on one only together with a signed seal or anchor from someone you trust. Without its anchor, a missing last row cannot be seen. |
| **NOT VERIFIED** / **NOT INTACT** | At least one check failed. The reasons are listed. Do not rely on the receipt. |
| **UNGROUNDED** (next to a file) | That source file is not the file the receipt names: it was changed or swapped. |
| **UNCHECKED** (next to a file) | That file was not given to the checker, so it was not compared. |
| **AFFECTED** | You entered something that was revoked (for example a source later found to be unreliable). The listed steps depend on it, directly or through another step. |

Steps in a case handoff are numbered from 0.

## What a receipt does not prove

- **Who signed it, as a person.** It proves which key signed it. A receipt says `ID_UNCHECKED`
  unless an identity check was done. Get the signer's key from a source you trust.
- **Exactly when it was made.** Times in a receipt are written by the signer (`self-asserted`).
- **That the content is true.** It proves the record has not been changed, not that what it
  records is correct.

## Checking the checker

Checking a download with that same download proves nothing: a forged checker could say anything,
including that it is genuine. Check your downloads with tools you already trust.

Each release lists every download, with its SHA-256, in `MANIFEST.sha256`, and seals that list in
`RECEIPT.json` with BYOAI's key. The list's own SHA-256 is recorded inside the seal as `manifest_sha256`.

- **Linux, the full check in one command:** `byoai-release verify <download folder> --pubkey <BYOAI's key>`,
  using a `byoai-release` you already trust: one you built yourself from the source (see the README),
  or one from a release you checked before. It checks the signature and every file. The folder must
  hold only that release's files: any other file is reported as added, and the check fails.
- **Any system, by hand:**
  1. Compute the SHA-256 of each downloaded file and compare it with its line in `MANIFEST.sha256`.
     Windows (PowerShell): `Get-FileHash <file>`. Mac: `shasum -a 256 <file>`. Linux: `sha256sum -c MANIFEST.sha256`.
  2. Compute the SHA-256 of `MANIFEST.sha256` itself and compare it with `manifest_sha256` in
     `RECEIPT.json` (open it in any text editor).
  3. The same file list is printed in the release notes on GitHub.
  4. Then check the signature in `RECEIPT.json` with a checker you already trust, for example
     a copy you checked before or one you built yourself.

## On the command line (Linux)

The release also has ready-to-run Linux programs (x86_64, no install needed):

```sh
chmod +x byoai-chain_v0_2_1_linux-x86_64
./byoai-chain_v0_2_1_linux-x86_64 verify --format handoff case.json --pubkey <key> --sources <folder>
./byoai-chain_v0_2_1_linux-x86_64 taint case.json --pubkey <key> --revoked revoked.json
```

On Windows and Mac, use the web checker. It runs the same verifier, compiled for the browser, and
gets the same answers from it (with single source files chosen, it matches them by name only). To build the command-line tools yourself, see the
[README](../README.md#build-and-test).
