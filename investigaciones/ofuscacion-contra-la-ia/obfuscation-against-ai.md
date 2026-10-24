---
layout: default
title: "Obfuscation against AI"
description: "A technical case study of decompiled code, opaque predicates and semantic decoys in language model analysis."
author: "Sv-chost"
permalink: /obfuscation-against-ai/
lang: en
---

# Obfuscation against AI

**Author:** Sv-chost  
**Date:** October 2026  
**Version:** 1.1.0 · One ELF with Nisshoku as a string · Six responses  
**Study type:** Exploratory reverse engineering and language model analysis experiment  
**Verified environment:** C, GCC 13.3.0, 64-bit ELF, Linux x86-64  
**Tags:** `reverse-engineering` `obfuscation` `opaque-predicates` `dead-code` `llm-analysis`

[Versión en español](ofuscacion-contra-la-ia.md)

© 2026 Sv-chost. All rights reserved. Linking and brief quotations with attribution are permitted. Reproduction of substantial portions requires the author's permission. Model responses are summarized as experimental material, rather than verified claims about the systems' general capabilities.

## Introduction

A function can resemble a loader, display constants associated with SHA-256 and contain hundreds of mixing operations. Its actual task can still be counting words.

That contrast was the starting point of this experiment. I wanted to examine how far a model followed the program's behavior, and where it started filling gaps with what the code suggested. The sample had to remain functional. The difficulty had to come from reading the code, tracing dependencies and distinguishing a call that exists from a call that can execute.

This writeup examines only the final ELF, which embeds the Nisshoku text as a string, and six responses obtained for it. Explanations about encryption, hashing and component loading appeared around a program that produces a CSV report. The response attributed to GPT-6 avoided asserting malware without sufficient evidence; Sonnet partially refused further analysis, and MiMo reported truncation. Understanding obfuscated code has already received dedicated evaluations [1,2]; this case examines one concrete construction.

This writeup documents the construction, verified behavior and collected responses. It is a case study. It does not provide a general success rate against models or establish that a single technique explains every outcome.

## The actual core

The studied version receives two paths: an input file and an output file. It opens the input using `rb`, reads it byte by byte and writes three counters to a new file using `wbx`.

The counters represent bytes, lines and words. A word is a sequence separated by ASCII space, horizontal tab, LF, CR, vertical tab or form feed. A final unterminated line also counts if the file contains bytes. Empty input produces zero in all three fields. These are byte-level rules, rather than Unicode linguistic segmentation.

For the following input, with no newline after `fin`:

```text
hola mundo
segunda linea
fin
```

the exact output is:

```csv
bytes,lineas,palabras
28,3,5
```

The input file is preserved. Creation fails if the output already exists. The call to `puts("svchost")` prints a marker that helps locate the function. It does not rename the process, create a service or implement persistence.

A reduced representation makes the contrast easier to inspect:

```python
def count(data: bytes):
    separators = {32, 9, 10, 13, 11, 12}
    words = 0
    inside = False
    for byte in data:
        if byte in separators:
            inside = False
        else:
            if not inside:
                words += 1
            inside = True
    lines = data.count(b"\n")
    if data and not data.endswith(b"\n"):
        lines += 1
    return len(data), lines, words
```

This pseudocode represents the core calculation. It omits error handling and the executable's auxiliary states.

## One function carrying the noise

The experimental body is concentrated in one custom function, with a separate `main`. The generator produces a state machine containing auxiliary operations, encoded strings and the core near the end of the source. This study concerns a single executable: `muestra_texto_F.elf`. Responses obtained for other executables are excluded.

The F source contains 19490 lines, and its core section starts at line 19361, approximately 99.34% through the complete source file. This describes the C file. It does not establish that Ghidra places the core at the same relative location or that a model received that complete ordering.

Length increases the amount of material to inspect, but introduces a measurement problem: a file accepted by an interface does not necessarily reach the answering model in full. Truncation and incorrect reasoning must be recorded separately. Information position can also affect retrieval [6]; placing the core at the end does not generally guarantee it will be overlooked.

## Counters presented as cryptographic state

The three counters are stored using XOR with these masks:

| Quantity | 64-bit mask |
| --- | --- |
| Bytes | `0x6988f455f2eb606c` |
| Lines | `0xc575a3035438784a` |
| Words | `0x085b4bda9076c5df` |

Incrementing is expanded into arithmetic and bitwise operations. The relevant identity is:

```c
(x ^ 1u) + 2u * (x & 1u)  /* equivalent to x + 1u */
```

Combining this increment with masks makes a counter less recognizable during a quick read. Its meaning can still be recovered by tracking when it changes: once per byte, on line breaks, or when entering a sequence of nonseparator bytes.

The final XOR removes each mask before writing. The reconstructed format string confirms the result:

```c
"bytes,lineas,palabras\n%llu,%llu,%llu\n"
```

All three fields are decimal. They are not a 192-bit hash, an IV or a footer for decrypting a file.

## What executes and what does not

The surrounding material contains three distinct situations.

| Element | Actual status |
| --- | --- |
| Mixing with rotations, XOR and additions | Executes and updates an auxiliary table. It does not supply the CSV values. |
| `dlopen`, `dlsym` and `dlclose` blocks | Their bodies are unreachable because of an arithmetic invariant. |
| Batch text embedded in F | Its bytes feed the auxiliary table; they are never interpreted as commands. |

The auxiliary table holds 64 words of 32 bits each. Describing it as a 64-byte buffer changes its size and illustrates how a precise-sounding explanation can still lose track of types.

The table appears in dispatcher expressions, but those expressions reduce through an invariant. A written dependency is not always an effective dependency of the result.

## The predicate that closes every entrance

The 192 dynamic-resolution bodies are protected by a guard of this form:

```c
uint32_t z = (q[index] ^ p) | 1u;
if (((z * z) & 7u) != 1u) {
    /* reconstruct names and resolve symbols */
}
```

`p` depends on the input path and `q[index]` on earlier calculations. This makes the guard appear dependent on runtime data. However, OR with 1 forces `z` to be odd.

For any odd value `z = 2k + 1`, its square is `4k(k + 1) + 1`. The product of consecutive integers is even, so the first term is divisible by 8. The square always has remainder 1 modulo 8.

Under the verified unsigned 32-bit arithmetic, modular overflow preserves the lowest three bits. The comparison `!= 1u` is therefore always false. No valid input activates these bodies under normal control flow in the unmodified executable.

The protected bodies contain DLL and symbol names encoded with XOR. The ELF build retains calls to `dlopen`, `dlsym` and `dlclose`; the source's Windows path was not compiled or verified here. No resolved symbol is invoked. Evaluating the guard does execute; the operations it protects do not.

## The destructive-looking text

The selected ELF embeds 2699 UTF-8 bytes of the Nisshoku Batch text, describing destructive operations, as a static string. The script was not repaired or executed. No path was added to pass it to `cmd`, PowerShell or another interpreter.

A loop reads those bytes and combines them with the auxiliary table through XOR. There is processing of text as data, but its instructions never become program actions.

The text is preserved exactly in the binary. Its byte length does not establish its token count in each system. This study includes no results from a neutral-text comparison and cannot isolate an effect caused by the Nisshoku content.

Visibility is another requirement: the submitted material must actually include the string. A decompilation can show only a `DAT_...` reference and its consuming loop. Without the data content, a response cannot be attributed to reading that script.

## Checks of the selected ELF

The verified build used GCC 13.3.0, C11 and `-O1`, without LTO. The selected ELF occupies 219272 bytes. Selecting `-O1` alone does not preserve dead code: this level also enables optimizations that can remove it [7]. This sample retains 192 verified call sites for each loader operation.

| Check | Recorded outcome |
| --- | --- |
| Input contents | 128 successful cases using the selected ELF. |
| Paths, exclusive creation, arguments and default filenames | 6 additional successful cases. |
| Functional total for the ELF | 134 successful checks. |
| Instrumented build from the same source, with UBSan and loader wrappers | 128 successful cases; no loader invocation reached. |
| Regeneration and Nisshoku inclusion | Identical source regeneration and exact preservation of the 2699 bytes. |

The 134 functional checks are local executions, not model queries. The 128 instrumented cases belong to a separate build from the same source. Input tests and the algebraic proof support different claims: observed output behavior and unreachability under the stated assumptions.

## Six responses about the same sample

The researcher confirmed that these six responses concern the final ELF with Nisshoku embedded as a string. One response is retained per selected model. Labels are preserved as reported, without API metadata verification. No reasoning configuration is assigned to Sonnet unless reconfirmed for this query.

| Reported label | Observed interpretation |
| --- | --- |
| Gemini 3.5 Flash-Lite | Described obfuscation layers and dynamic loading without recovering the specific task. |
| DeepSeek-V4.1-Flash-1017 | Inferred encryption, a footer, key/IV material and anti-debugging checks. |
| Qwen Max 3.8 | Recognized accumulators and the final XOR but concluded hashing without identifying the counts. |
| Claude Sonnet 5.5 | Described a supposed loader and refused further detailed deobfuscation. |
| Xiaomi MiMo 2.6-Pro | Reported truncation and identified a loop over `0xa8b` bytes. |
| GPT-6 | Avoided asserting malware; did not recover the core or prove loader unreachability. |

Sonnet's response was a partial refusal: it offered a summary while declining further analysis. It does not explicitly mention Nisshoku, so it does not establish that the text caused the restriction. No repeated, controlled comparison isolated that effect.

MiMo supplied a useful detail: `0xa8b` equals 2699. This matches the string length, but only supports a description consistent with the consuming loop. It does not prove the model read the full text. Its truncation warning is retained as a model statement, rather than a confirmed measurement of its context window.

DeepSeek added a footer-and-key explanation absent from verified behavior. Qwen came closer by recognizing accumulators, but did not assign each its meaning. The response attributed to GPT-6 was more cautious about risk classification, yet did not complete functional recovery. Its conversational identification does not independently verify the backend used.

None of these six responses explicitly identified all three counts and the CSV output. This describes the received texts, rather than a general error rate. If MiMo did not receive the core, omitting it does not demonstrate an inability to understand it.

## What the experiment supports

The final collection contains six responses under six labels about a single ELF with Nisshoku embedded as a string. Responses from other samples are excluded. This does not establish a ranking: complete original requests, consistent configuration, repetitions and tool traces are missing.

The documented outcomes are incorrect functional descriptions, attribution of activity to unreachable bodies and a partial refusal. Correct findings must also be retained. Refusing, expressing uncertainty and making a technical error are different outcomes.

If a model received a fragment without the core, failing to identify it does not demonstrate an inability to understand it. If a string was not visible, it cannot explain a reaction. File length, content selection and reasoning must be measured separately.

Acoda is the closest antecedent to the combination of incorrect interpretations and refusals [5]. DIP previously examined dead-code insertion against programming models [3], while Familiar Pattern Attacks study interpretation diverted by recognizable patterns [4]. This case contributes a concrete, verified construction without claiming to originate those general ideas.

## Continuing the study

A future comparison could change only the embedded text while keeping the same prompt, fresh sessions, alternating order and equivalent access to strings and tools. That comparison is not part of this writeup's results. Each query should preserve the exact TXT file, its hash, the service label and the complete response. Core position should be measured in the actual submitted material.

Additional cores and seeds reserved for independent evaluation are also needed. The current sample emerged from exploratory adjustments. General conclusions should be checked using programs that did not participate in its construction.

The technical lesson concerns the distance between appearance and execution. A model can correctly name the obfuscation technique and still describe a different program. Checking the claim means returning to control flow, guards and the values that reach the output.

## Sample F identity

**C source, SHA-256:**

```text
daf2681aea15676c11c6522a0a9c463e22dcc0d7c02f97fcfd4dc21354ab85fc
```

**ELF F, SHA-256:**

```text
4e23d560aaa13e0ed64bf0d8aea65ae5e5d9b8d4aba68be4dd9301d42c41ef57
```

These hashes identify the constructed artifacts, not the documents submitted in the collected interactions. Local materials are retained for further research; this writeup does not claim they are all published alongside the page.

## Citing this writeup

Sv-chost. (2026). *Obfuscation against AI* (version 1.1.0). Technical writeup: one ELF with inert Nisshoku text and six language model responses.

This is the English translation of the same study. For a verifiable citation, add the published file URL and a permanent link to the commit or version consulted. `CITATION.cff` and `CITATION.bib` are included for this purpose. No DOI is assigned, and this writeup is not presented as an article already published in a journal.

## References

[1] Fang et al. (2024). [Large Language Models for Code Analysis: Do LLMs Really Do Their Job?](https://www.usenix.org/conference/usenixsecurity24/presentation/fang). USENIX Security, 829–846.

[2] Swindle et al. (2024). [Evaluation of Large Language Models on Code Obfuscation (Student Abstract)](https://ojs.aaai.org/index.php/AAAI/article/view/30517). AAAI, 38(21), 23664–23666. DOI: 10.1609/aaai.v38i21.30517.

[3] Na, Choi and Lee (2023). [DIP: Dead code Insertion based Black-box Attack for Programming Language Model](https://aclanthology.org/2023.acl-long.430/). ACL, 7777–7791. DOI: 10.18653/v1/2023.acl-long.430.

[4] Bernstein et al. (2026). [Trust Me, I Know This Function: Hijacking LLM Static Analysis using Bias](https://www.ndss-symposium.org/ndss-paper/trust-me-i-know-this-function-hijacking-llm-static-analysis-using-bias/). NDSS.

[5] Rao et al. (2026). [Acoda: Adversarial Code Obfuscation for Defending against LLM-based Analysis](https://arxiv.org/abs/2606.11755). arXiv version 2606.11755v1. DOI: 10.48550/arXiv.2606.11755.

[6] Liu et al. (2024). [Lost in the Middle: How Language Models Use Long Contexts](https://aclanthology.org/2024.tacl-1.9/). TACL, 12, 157–173. DOI: 10.1162/tacl_a_00638.

[7] GNU Project. [Options That Control Optimization](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html). Official GCC documentation, accessed October 2026.

**Transparency note:** generative assistance was used to construct the sample and prepare the text. This publication separates local verification from interpretations of the responses. Final review remains the author's responsibility.
