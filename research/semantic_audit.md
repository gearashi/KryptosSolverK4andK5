# Independent checks on the proposed word-to-symbol layer

Checkpoint K4-20261012-F. No decipherment is claimed.

## Standard NATO spelling words

The [official NATO source](https://www.nato.int/en/news-and-events/articles/news/2017/12/21/nato-phonetic-alphabet-codes-and-signals) fixes the alphabet. ENE is spelled Echo November Echo, and BC is Bravo Charlie. East, Northeast, Berlin, and Clock are not its designated letter words.

A stronger exact check does not need word boundaries. Any two adjacent letters in a concatenated stream of these 26 words must occur inside a word or across one word's last letter and the next word's first letter. Enumerating both finite sets gives no ST or NC. Thus EASTNORTHEAST and BERLINCLOCK cannot occur even as substrings of that stream. The code also finds HE impossible in the first phrase. This excludes the literal 97-letter plaintext being entirely such a stream, regardless of how its word boundaries are placed.

[The script](nato_constraints.py) independently constructs the pair set by concatenating all 676 ordered word pairs, and checks EchoNovemberEcho and BravoCharlie as positive controls. The normalized spellings, complete pair sets, witnesses, and scope are in the [saved result](runs/nato-001/results.json). Its [validated manifest](runs/nato-001/manifest.json) records the script hash, environment, and bounded execution. Root independently implemented the pair check after the reviewing agent identified the witnesses.

This result does not exclude mixed ordinary prose and codewords, another spelling alphabet, number words, a custom codebook, initials, or a separate intermediate text. It gives no claim about arbitrary military codes.

## What remains open

The [abbreviation audit](semantic_constraints.md) distinguishes taking word initials, splitting compounds, mapping whole phrases, and using derived strings as encryption keys. These are different models and must not exchange evidence silently. A useful custom-codebook hypothesis needs an independently motivated dictionary, segmentation, and handling of unmatched text, followed by a prediction beyond the two known phrases.

The [creator's letter](../docs/SEMANTIC_SOURCES.md) supports further interpretation and an announced 97-character K5. It does not provide the proposed ENE/BC transformation or the K5 ciphertext. All original 24 K4 crib letters remain unchanged.
