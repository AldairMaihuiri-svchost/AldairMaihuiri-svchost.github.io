---
title: "Ransomware Red Teaming — Module 8: Ransom Notes and Coercive Communication"
description: "Analysis of messages, identifiers, visual channels, evidence, and synthetic-record exercises on Windows 11."
author: Aldair Maihuiri
---

# Module 08 — Ransom Notes and Coercive Communication

A ransom note is a communication artifact produced during an extortion operation. It may describe files allegedly encrypted, present an identifier, propose a contact channel, and announce deadlines or consequences. Each statement reflects **a claim by its author**; the document alone does not prove that data were exfiltrated, that a working recovery tool exists, or that a stated deadline will be enforced.

[Module 07](Ransomware-Modulo7-en) distinguished secrets, public metadata, and verifiable recovery. Here we examine how a message can refer to a session identifier without becoming part of the cryptographic protocol itself. [Module 04](Ransomware-Modulo4-en) showed that discovering a directory does not prove its files were processed; finding a note there does not establish that all its files were transformed either. [Modules 05](Ransomware-Modulo5-en) and [06](Ransomware-Modulo6-en) provide the task states needed to interpret when an artifact was created.

The practical exercise analyzes **synthetic notices** and their relationship to local evidence. It publishes no messages, changes no desktop settings, and contacts no one. The goal is to separate claims, observations, and inferences while recognizing errors in Windows 11 code examples.

## 8.1 Message functions and evidentiary limits

| Observable element | Possible function for the sender | What an analyst can verify |
| --- | --- | --- |
| Encryption claim | Communicate an alleged impact | Compare originals and outputs, task states, and observed operations. |
| Session or victim ID | Link message and record | Check its format and whether it matches exercise metadata. |
| Contact channel | Propose a way to negotiate | Record its presence literally; do not assume it works or identifies a group. |
| Deadline or threatened increase | Compress decision time | Identify the threat and context; do not infer automatic enforcement. |
| Publication threat | Add reputational pressure | Look for independent evidence of extraction or disclosure. |
| Offer of a recovery demonstration | Attempt to establish credibility | Distinguish an offer, a demonstration received, and verified recovery of authorized data. |
| Instructions against modifying files | Influence the response | Check whether they have a technical basis in the observed format. |

These elements may be combined or entirely absent. The absence of a note does not prove that no transformation occurred: execution may have stopped before note creation, the message may have been stored elsewhere, or the analyst may lack access to its location. MITRE ATT&CK describes note creation and other changes as possible observations associated with data encryption for impact; their presence calls for temporal and technical correlation. [MITRE ATT&CK T1486](https://attack.mitre.org/techniques/T1486/).

### Psychological pressure: what to analyze

A deadline, a publication threat, or a personalized message seeks to influence decisions under uncertainty. A rigorous analysis describes **the pressure mechanism** and evidence of its use without accepting the sender's promises or threats as facts. Pressure may fall on technical staff, executives, public-facing personnel, or people whose information is mentioned. The Jigsaw case in Module 01 offers a comparison between presenting progressive loss to an individual and threatening disclosure or disruption to an organization.

Record separately the recipient, claim, threatened consequence, deadline, fact used to make the message seem credible, and response it seeks. The coercive pattern can remain recognizable as algorithms and platforms change. Nor is the document an automatic attribution mechanism: a template can be copied, modified, or reused.

## 8.2 Documented samples and attribution

When using a note associated with a known family, a publishable module should identify **source, date, variant, and scope**. An editorial “LockBit-style” note is an illustration, not an authenticated original. CISA and partner agencies have documented LockBit 3.0 samples and artifacts; any comparison with a real specimen should link to the specific report and distinguish quotations, paraphrases, and teaching additions. [CISA/FBI/MS-ISAC: LockBit 3.0](https://www.cisa.gov/sites/default/files/2023-03/aa23-075a-stop-ransomware-lockbit.pdf).

| Evidence level | Example | Careful conclusion |
| --- | --- | --- |
| Matching text | A phrase or title appears in two notes | Text matches; it may have been copied. |
| Matching format | Similar identifiers and layout | Hypothesis of a common template requiring more samples. |
| Corroborated artifacts | Note, file, process, and times linked | That sequence occurred in the observed case. |
| Family attribution | Several documented technical traits match | Attribution with uncertainty and alternatives stated. |

For a family comparison, select two or three notices from primary reports and build a matrix of fields and variations. Do not assign payment rates, preferred filenames, or exclusive tactics without sources. Summarize and cite extensive third-party text instead of reproducing it in full.

## 8.3 Identifiers: text, bytes, and correlation

A 16-byte `session_id` can be represented in hex or Base64; a serialized 72-byte ECDH public key can also be encoded in Base64. **They are different objects.** Once its encoding is known, a string's length can support a hypothesis, but it does not establish which object was used. Examine where the value comes from and which footer or register field it matches.

| Object | Purpose | Consequence of confusion |
| --- | --- | --- |
| Opaque session ID | Find a case or link records | A reused or changed ID can conflate distinct cases or split one session. |
| Ephemeral public key | Repeat an agreement with the corresponding private key | Treating it as merely an ID can conceal a recovery dependency. |
| Contact address | Sender-declared channel | Does not establish identity or availability. |
| Sample fingerprint | Distinguish files under analysis | Is not the ID shown by a note. |

A note using an ID created before a footer was saved may remain visible even if the later write failed. An account of the incident should therefore track **note ↔ record ↔ verified entries**, with missing links stated explicitly. No visit to an address within the message is needed for this analysis.

## 8.4 Presentation surfaces on Windows 11

**Plain text.** A `.txt` file may appear in processed directories, on the desktop, or in a shared location. Inspect its name, contents, encoding, timestamps, and write result. With `CREATE_ALWAYS`, a repeated execution may overwrite an earlier note. Checking both the result of `WriteFile` and the number of bytes written matters as much as calculating an ID. A formatting function that returns a negative value on truncation must never have that value converted unchecked into a write length.

**Desktop.** Wallpaper can act as a visual notice and an investigative artifact. Drawing into a GDI context does not automatically produce a BMP file: generating, saving, and selecting an image are separate steps. `SystemParametersInfoW(SPI_SETDESKWALLPAPER)` operates on a path and in a user context; observed appearance may depend on the session, policy, and configuration. Microsoft recommends `SHGetKnownFolderPath` and `FOLDERID_Desktop` for new code; `CSIDL` APIs remain for compatibility. [Microsoft: Known Folders](https://learn.microsoft.com/en-us/windows/win32/shell/known-folders); [SystemParametersInfoW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow).

**HTA.** An HTML application run by `mshta.exe` is a different artifact from an inert HTML page. It can contain scripts and operations involving files or the registry. A VBScript example requires historical context: Microsoft has announced its deprecation and a phase as an optional Windows feature. A Windows 11 lesson should treat HTA as a legacy format and execution surface, using inert HTML to display test content. Running an HTA is unnecessary to classify its fields. [Microsoft: VBScript status](https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features-resources#vbscript).

### Distribution, duplicates, and permissions

A list of adjacent directories does not establish global deduplication. A program comparing only with `lastDir` avoids two consecutive writes to the same directory but does not recognize a later return to it. A fixed array holding thousands of paths can exhaust stack space or reach capacity before covering the set. Drive letters returned by `GetLogicalDrives` do not include every UNC path or mounted location, as discussed in Module 04.

To analyze distribution, compare **directories observed**, **writes attempted**, **writes completed**, and **notes verified**. A directory may reject creation because of permissions, disappear, or fall outside authorized scope. The count of notes is not a count of affected files.

## 8.5 Lab: synthetic messages and evidence

The following Python 3 program uses only the standard library. On Windows 11, run `py -3 lab_module8.py`. It creates three fictional records in a temporary directory, which is removed when the program finishes. The terms `encryption` and `publication` are **claims inside the exercise**, not actions taken by the program. There are no contact addresses or system interface changes.

```python
"""Synthetic notice analysis. Writes only inside a temporary directory."""
import json
import tempfile
from pathlib import Path

FIXTURES = [
    {"id": "S-101", "channel": "text", "claims": ["encryption", "publication"],
     "observed": ["notice_found"], "label": "A"},
    {"id": "S-101", "channel": "desktop", "claims": ["encryption"],
     "observed": ["notice_found", "image_file_found"], "label": "B"},
    {"id": "S-202", "channel": "text", "claims": ["publication"],
     "observed": ["notice_found"], "label": "C"},
]

def check(item):
    required = {"id", "channel", "claims", "observed", "label"}
    if set(item) != required or not isinstance(item["id"], str):
        raise ValueError("BAD_SCHEMA")
    if not isinstance(item["claims"], list) or not isinstance(item["observed"], list):
        raise ValueError("BAD_SCHEMA")
    unsupported = sorted(set(item["claims"]) - set(item["observed"]))
    return item["id"], item["channel"], unsupported

with tempfile.TemporaryDirectory(prefix="module8_") as directory:
    root = Path(directory)
    for item in FIXTURES:
        (root / (item["label"] + ".json")).write_text(
            json.dumps(item, ensure_ascii=False), encoding="utf-8")
    for path in sorted(root.glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        session, channel, unsupported = check(record)
        print(path.stem, session, channel, "CLAIMS_WITHOUT_LOCAL_PROOF", unsupported)
    changed = json.loads((root / "A.json").read_text(encoding="utf-8"))
    changed.pop("id")
    try:
        check(changed)
    except ValueError as exc:
        print("Incomplete record:", exc)
```

Records A and B share an ID, which establishes only a textual match within this collection. In all three cases, claims about encryption or publication lack local proof in the records. The fourth result shows that correlation is rejected when the ID is missing. The code is not a malware detector: it teaches how to state a conclusion in proportion to the evidence.

### Variations to repeat

1. Add a fourth record with another `label` and ID `S-101`; compare grouping by ID and by channel.
2. Change B's `id` to `S-202`. Which hypothesis about the relationship between A and B is no longer supported?
3. Separately record a disposable file with a known digest and a verifiable `observed` field; explain why a matching note cannot substitute for a comparison of data.
4. Add fictional timestamps for “note created,” “entry examined,” and “outcome verified.” Ordering them does not authorize inventing an event that was never observed.

| Case | Claim | Local evidence | ID link | Limit of conclusion |
| --- | --- | --- | --- | --- |
| A | Encryption and publication | Note present | S-101 | Neither encryption nor publication is established. |
| B | Encryption | Test note and image present | S-101 | Two notices can share an ID without proving impact. |
| C | Publication | Note present | S-202 | The declared threat needs independent, authorized corroboration. |

## 8.6 Chronology, provenance, and contradictions

Communication need not match the technical state of an operation. Build a case chronology from **observed** times and their sources: notice acquisition, file creation time, recorded write attempt, confirmed result, image acquisition, and verification of a specific entry. Record time zone, clock resolution, and possible skew between machines. A copied file's timestamp may reflect the copying event; it is not automatically the time when the notice first appeared.

| Observation | Possible interpretation | Remaining check |
| --- | --- | --- |
| Two notices have the same ID but different text | A template changed, a retry occurred, or an ID was reused | Compare hashes, trustworthy times, and session metadata. |
| A folder contains a notice but no verified result | The notice was written first, processing stopped, or files were skipped | Examine states, errors, and enumeration coverage. |
| An image exists on disk but is not on screen | Selection failed, another user session is active, or policy intervened | Separate file creation from visual activation. |
| A notice claims an external copy exists | This may be a threat without proven extraction | Correlate authorized transfer logs and independent sources. |

Do not resolve an apparent contradiction by choosing the most dramatic explanation. For example, a notice acquired at 12:10, an output file modified at 12:08, and a desktop screenshot captured at 12:14 order **those three observations**. They establish neither the start of processing, the number of completed entries, nor whether anyone saw the message at 12:08. A report records alternatives, evidence that could distinguish them, and unavailable information.

Acquisition method also matters. Keep a working copy, its hash, its source path, and the method used to obtain it. For text, record bytes, apparent encoding, and line-ending normalization; a string search can miss UTF-16 or text rendered into an image. Static inspection of HTML or HTA is different from script execution. A screenshot shows the pixels visible in one session at one moment, while the underlying file can expose properties the screenshot does not show. Keep content, representation, and behavior separate.

**Interpretation exercise.** Consider four fictional observations: A and B share `S-101`; B contains `image_file_found`; an entry associated with `S-101` is recorded only as `attempted`; and C claims publication under `S-202`. Write two finding sentences, one about the matching identifiers and one about the entry outcome. The first may state that A and B show the same ID text. The second may only state that an attempt was recorded. C's claim provides no proof of publication. Repeat after changing B to `S-202` and identify which connection is no longer justified.

## 8.7 Publication timing and notice scope

Creating a notice is an event with its own state, not an automatic consequence of data transformation. A workflow may prepare text before examining entries, write it while work remains pending, or publish it after a verified result. Each ordering produces a different relationship among **visible message**, **session state**, and **confirmed results**. An interruption may leave notices without affected files or affected files without a notice. A notice in every folder multiplies artifacts and permission failures; one desktop notice depends on the user's session. Neither distribution guarantees that a recipient saw it.

| Observed time | Interpretation risk | Evidence to preserve |
| --- | --- | --- |
| Before operations | A notice can announce results that never occurred | Creation time, issued ID, and later per-entry state. |
| While operations are pending | Coverage changes after the notice already exists | In-flight states, errors, and each observation time. |
| After a verification | Earlier results may be absent from the notice | Selection rule, confirmations, and publication failures. |
| Following a retry | Conflicting texts or IDs may coexist | Versions, hashes, and the link of each notice to its session. |

An authorized exercise **models these states** with the lab's synthetic records without creating or distributing extortion messages. Add a fictional `phase` field (`prepared`, `pending`, `verified`) and compare each record's claims with its phase. The reporting goal is to explain an interrupted sequence without inventing completed operations.

## 8.8 Channels, claimed identity, and recovery demonstrations

A notice may name email, a web portal, an anonymous service, or a conversation identifier. Classify these as **declared channels**, not proof of a verifiable counterparty. An infrastructure analysis preserves the text, domain or identifier, observation date, link to the sample, and changes between variants; the lab establishes no communication. One reused channel does not identify an individual by itself, and multiple channels do not prove different operators. A channel's exposure and possible expiry affect interpretation of a notice found months later.

Offers to “decrypt a sample file” need three separate events: the **offer in the notice**, **verifiable delivery of a sample**, and **confirmed restoration**. Only the third, with known original bytes and custody, supports the claim that this particular case was reconstructed. It does not prove all files can be restored. In an authorized simulation, the client specifies a disposable file, its hash, the protocol version, and a validation method independent of the notice's channel in advance. Key, identifier, nonce, and metadata requirements connect to Modules 03, 07, and 09; their absence may make recovery impossible despite the message's promise.

Language is another sample attribute: record whether text is fixed, occurs in several versions, or was observed to vary with regional settings. An awkward translation may suggest template reuse but does not prove geographical origin. Personalization with an organization's name, data excerpts, or an apparent deadline requires corroborating the provenance of **each field**. A displayed countdown does not prove that any subsequent action is automated.

## 8.9 Documented comparison and cautious attribution

| Case and source | Published observation | Limit of comparison |
| --- | --- | --- |
| [LockBit 3.0, 2023 joint advisory](https://www.cisa.gov/sites/default/files/2023-03/aa23-075a-stop-ransomware-lockbit.pdf) | Describes a note dropped after file encryption with a name linked to an ID. | Does not establish that all variants and affiliates used the same sequence. |
| [RansomHub, 2024 joint advisory](https://www.cisa.gov/sites/default/files/2024-09/aa24-242a-stopransomware-ransomhub-ransomware_1.pdf) | The note described during encryption generally lacks an initial monetary demand. | Do not invent fields or extrapolate to every incident. |
| [CL0P and MOVEit, 2023 joint advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a) | The documented campaign focused on data theft; extortion does not always follow per-file encryption. | Do not force the campaign into a post-encryption notice template. |
| [ALPHV/BlackCat, 2024 update](https://www.cisa.gov/sites/default/files/2024-03/aa23-353a-stopransomware-alphv-blackcat-update_2.pdf) | Documents an extortion and affiliate context. | A family label cannot attribute an isolated note. |

Comparing **structure, order, and tone** in particular notes requires dated, verified copies of each variant; a general family advisory is no substitute for those samples. Record which fields are present and which are unknown. Claims that notes became “more aggressive” or “more professional” need a corpus, defined time period, and reproducible criteria. A planted copy, imitation, or template shared across affiliates can produce textual matches. Correlate ID, data format, process, chronology, and provenance before attribution.

Payment probability cannot be computed from one note either. A rate needs a denominator, an account of observation bias, a time period, and a confirmed outcome; subjective impressions of tone are not measurement. A report can measure how many notices were found, on which surfaces, which claims were corroborated, and how many recipients or systems were exposed according to authorized evidence.

## 8.10 Report and Xtra questions

An analysis record should preserve sample provenance, date and variant; a copy and digest of the note; encoding; extracted fields; observed locations and times; links to other artifacts; uncorroborated claims; and confidence level. Describing coercion calls for attention to the recipients and the uncertainty imposed on them as well as to the bytes of the message.

## Xtra:

1. What relationship would an operator have to establish between a note ID and session material to avoid linking a message to another execution?
2. What does a scheme lose if it publishes a note before confirming the state of the results it describes?
3. If a publication threat appears in a note, what further evidence would separate communicative pressure from confirmed extraction?
4. How does interpretation change when two notes share text but their identifiers and technical artifacts do not match?
5. How does the choice of several visual channels affect the ability to correlate notices from one session?
6. Why does a note in every directory fail to establish that every file in those directories was processed?
7. Which operational decision is revealed when a template displays an ephemeral public key instead of an opaque ID?
8. What would have to happen for a deadline announced in the message to correspond to a verifiable change in the operation's state?
9. If notices are published before results are verified, which contradictions can arise after an interruption?
10. Which observations distinguish the offer of a recovery demonstration from confirmed restoration?
11. What evidence would distinguish a reused template from a note attributable to a particular variant?

## Module 08 summary

A note communicates claims and may apply pressure; its presence does not establish those claims. Publication, distribution, channels, language, and recovery offers each have their own states and evidentiary requirements. Identifiers must be linked to records and observed files. On Windows 11, text, wallpaper, and HTA have different artifacts. Family comparisons need particular samples and dates; the lab separates message, evidence, and limits of inference.

## Technical references

- [MITRE ATT&CK T1486: Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/).
- [CISA/FBI/MS-ISAC: LockBit 3.0](https://www.cisa.gov/sites/default/files/2023-03/aa23-075a-stop-ransomware-lockbit.pdf).
- [CISA/FBI/MS-ISAC/HHS: RansomHub](https://www.cisa.gov/sites/default/files/2024-09/aa24-242a-stopransomware-ransomhub-ransomware_1.pdf).
- [CISA/FBI: CL0P and MOVEit](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a).
- [CISA/FBI/HHS: ALPHV/BlackCat](https://www.cisa.gov/sites/default/files/2024-03/aa23-353a-stopransomware-alphv-blackcat-update_2.pdf).
- [Microsoft: Known Folders](https://learn.microsoft.com/en-us/windows/win32/shell/known-folders).
- [Microsoft: SystemParametersInfoW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow).
- [Microsoft: VBScript deprecation resources](https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features-resources#vbscript).

© 2026 Aldair Maihuiri. All rights reserved. Sharing with attribution to the author is permitted. Reproduction without prior authorization is prohibited.
© 2026 Aldair Maihuiri. Todos los derechos reservados. Se permite compartir con atribución al autor. La reproducción sin autorización previa está prohibida.
