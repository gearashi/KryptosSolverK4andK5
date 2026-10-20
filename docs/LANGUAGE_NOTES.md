# Language assumptions for K4 and K5

Bounded source review: **12 October 2026**. This note changes no ciphertext, crib, or pinned computation input.

## K4: direct support for English

In Kim Zetter's **21 January 2005** [WIRED interview with Ed Scheidt](https://www.wired.com/2005/01/inside-info-on-kryptos-codes/), the cryptographic adviser states: **“All four (sections) are done in the English language.”** This is direct testimony about K1–K4, beyond an inference from the released English cribs. He describes concealing recognizable English statistics in K4. Later answers acknowledge that he had not checked Sanborn's final modifications. The interview supports English as the leading plaintext assumption; it does not specify every final transformation or require ordinary prose at every intermediate stage.

The published K4 cribs remain exact: EAST at 22–25, NORTHEAST at 26–34, BERLIN at 64–69, and CLOCK at 70–74 (one-based). A French, Spanish, Latin, or mixed-language hypothesis must still explain those fixed letters. The Latin alphabet is a writing system, not a guarantee of any particular natural language.

## K5: keep the question open

The [current owner's June 2026 statement](https://www.paradigm.xyz/writing/kryptos) describes a further 97-character ciphertext from Sanborn with a planned future release. This bounded review has no authenticated public K5 ciphertext or explicit primary statement fixing its language. Scheidt's 2005 statement about four sections should not be extended to this later-described K5. The owner's K4 form accepting uppercase A–Z is a character-format rule, not evidence for K5's natural language. Earlier uses of “K5” are distinguished in [RESEARCH.md](RESEARCH.md).

## Consequences for the investigation

- Exact contradiction checks against known K4 letters do not depend on an English frequency model. Changing the language of the unknown letters cannot rescue a contradiction within the same tested cipher model and bounds.
- A poor English score is a ranking signal, not a mathematical rejection. An intermediate result may retain another cipher layer or deliberate masking.
- Multilingual ranking is an optional exploration, especially for K5 once authenticated input exists. Keep its language assumptions explicit and separate it from exact crib tests.

No multilingual search was run for this source note. No candidate was submitted externally.
