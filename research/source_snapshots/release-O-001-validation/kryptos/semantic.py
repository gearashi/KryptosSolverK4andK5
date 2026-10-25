"""Bounded interpretation under explicit segmentation and declared rules.

No word segmentation, codebook, direction lookup, or K5 text is inferred.
Unrecognized segments stay verbatim in the output and have explicit coverage.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Iterable, Mapping


def _hash(value) -> str:
    serialized = json.dumps(value, sort_keys=True, ensure_ascii=True,
                            separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _partition(text, segments, max_characters, max_segments):
    if (type(max_characters) is not int or max_characters < 1
            or type(max_segments) is not int or max_segments < 1):
        raise ValueError("bounds must be positive integers")
    if not isinstance(text, str) or len(text) > max_characters:
        raise ValueError("text must be a string inside the character bound")
    partition, previous = [], 0
    for segment in segments:
        if len(partition) >= max_segments:
            raise ValueError("segment count exceeds bound")
        try:
            start, stop = segment
        except (TypeError, ValueError) as error:
            raise ValueError("each segment must be a (start, stop) pair") from error
        if (type(start) is not int or type(stop) is not int
                or start != previous or not start < stop <= len(text)):
            raise ValueError("segments must partition the entire text in order without gaps")
        partition.append((start, stop))
        previous = stop
    if previous != len(text):
        raise ValueError("segments must cover the entire text")
    return tuple(partition)


@dataclass(frozen=True)
class SemanticToken:
    start: int
    stop: int
    original: str
    replacement: str | None

    @property
    def recognized(self):
        return self.replacement is not None

    @property
    def output(self):
        return self.replacement if self.recognized else self.original


@dataclass(frozen=True)
class SemanticResult:
    rule: str
    rule_source: str
    rule_sha256: str
    input_sha256: str
    segmentation_sha256: str
    codebook: tuple[tuple[str, str], ...]
    rule_parameters: tuple[tuple[str, str], ...]
    tokens: tuple[SemanticToken, ...]
    unused_codebook_entries: tuple[str, ...]

    @property
    def transformed_text(self):
        """Includes unchanged unknowns; this is not a recovered message."""
        return "".join(token.output for token in self.tokens)

    @property
    def recognized_tokens(self):
        return sum(token.recognized for token in self.tokens)

    @property
    def covered_characters(self):
        return sum(token.stop - token.start for token in self.tokens if token.recognized)

    @property
    def input_characters(self):
        return self.tokens[-1].stop if self.tokens else 0

    def to_dict(self):
        result = asdict(self)
        result["codebook"] = dict(self.codebook)
        result["rule_parameters"] = dict(self.rule_parameters)
        result.update(
            schema="kryptos.semantic-extraction.v1",
            transformed_text=self.transformed_text,
            recognized_tokens=self.recognized_tokens,
            total_tokens=len(self.tokens),
            covered_characters=self.covered_characters,
            input_characters=self.input_characters,
            character_coverage=(self.covered_characters / self.input_characters
                                if self.input_characters else 0.0),
            token_coverage=(self.recognized_tokens / len(self.tokens)
                            if self.tokens else 0.0),
        )
        result["tokens"] = [dict(asdict(t), recognized=t.recognized, output=t.output)
                            for t in self.tokens]
        return result


def _extract(text, partition, codebook, rule, rule_source, parameters, max_characters):
    if not isinstance(rule_source, str) or not rule_source.strip():
        raise ValueError("rule_source must explicitly identify the rule's origin or hypothesis")
    if not isinstance(codebook, Mapping) or len(codebook) > max_characters:
        raise ValueError("codebook must be a bounded mapping")
    if any(not isinstance(k, str) or not k or not isinstance(v, str) or not v
           for k, v in codebook.items()):
        raise ValueError("codebook keys and replacements must be nonempty strings")
    if sum(len(k) + len(v) for k, v in codebook.items()) > max_characters:
        raise ValueError("codebook exceeds character bound")
    tokens, used, output_length = [], set(), 0
    for start, stop in partition:
        raw = text[start:stop]
        replacement = codebook.get(raw)
        token = SemanticToken(start, stop, raw, replacement)
        output_length += len(token.output)
        if output_length > max_characters:
            raise ValueError("transformed output exceeds character bound")
        tokens.append(token)
        if token.recognized:
            used.add(raw)
    return SemanticResult(
        rule, rule_source,
        _hash(dict(rule=rule, source=rule_source, codebook=dict(codebook), parameters=parameters)),
        hashlib.sha256(text.encode("utf-8")).hexdigest(), _hash(partition),
        tuple(sorted(codebook.items())), tuple(sorted(parameters.items())),
        tuple(tokens), tuple(sorted(set(codebook) - used)),
    )


def apply_codebook(text: str, segments: Iterable[tuple[int, int]],
                   codebook: Mapping[str, str], *, rule_source: str,
                   max_characters: int = 100_000,
                   max_segments: int = 10_000) -> SemanticResult:
    """Apply exact, case-sensitive mappings to a caller-fixed full partition.

    Segments are zero-based half-open spans in the original text. Include unknown
    regions as segments too. No trimming, resplitting, or partial token match is
    attempted. The returned token records preserve original offsets and text.
    """
    partition = _partition(text, segments, max_characters, max_segments)
    return _extract(text, partition, codebook, "explicit-codebook", rule_source,
                    {}, max_characters)


def extract_initials(text: str, segments: Iterable[tuple[int, int]], *, rule_source: str,
                     alphabet: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                     max_characters: int = 100_000,
                     max_segments: int = 10_000) -> SemanticResult:
    """Take one initial per fixed all-alphabet segment, preserving others.

    Matching is literal and case-sensitive. EAST|NORTHEAST yields EN;
    EAST|NORTH|EAST yields ENE. Neither segmentation is chosen by this function.
    Unknown alphabetic text must be represented by the codebook API instead:
    this rule intentionally treats every all-alphabet segment as a word.
    """
    if (not isinstance(alphabet, str) or not alphabet
            or len(set(alphabet)) != len(alphabet)):
        raise ValueError("alphabet must contain distinct symbols")
    partition = _partition(text, segments, max_characters, max_segments)
    codebook = {}
    for start, stop in partition:
        token = text[start:stop]
        if all(c in alphabet for c in token):
            codebook[token] = token[0]
    return _extract(text, partition, codebook, "fixed-segment-initials", rule_source,
                    {"alphabet": alphabet}, max_characters)


def main(argv=None):
    """Apply one explicit JSON semantic request; never search for a codebook."""
    import argparse
    from pathlib import Path
    import sys

    parser = argparse.ArgumentParser(
        description="Apply an explicit codebook or initialism to a fixed full partition.")
    parser.add_argument("--input", required=True,
                        help="JSON with method, text, segments, rule_source and codebook/alphabet")
    parser.add_argument("--output", default="-", help="new JSON file or - for stdout (default)")
    parser.add_argument("--force", action="store_true", help="allow replacing the output file")
    args = parser.parse_args(argv)

    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON field: {key}")
            value[key] = item
        return value

    def reject_constant(value):
        raise ValueError(f"nonstandard JSON constant: {value}")

    try:
        request = json.loads(Path(args.input).read_bytes().decode("utf-8-sig"),
                             object_pairs_hook=unique_object, parse_constant=reject_constant)
        required = {"method", "text", "segments", "rule_source"}
        if not isinstance(request, dict) or not required <= set(request):
            raise ValueError("semantic JSON requires method, text, segments and rule_source")
        method = request["method"]
        allowed = required | {"max_characters", "max_segments"}
        if method == "codebook":
            allowed.add("codebook")
            if "codebook" not in request:
                raise ValueError("codebook method requires an explicit codebook")
            function = apply_codebook
        elif method == "initials":
            allowed.add("alphabet")
            function = extract_initials
        else:
            raise ValueError("method must be codebook or initials")
        if set(request) - allowed:
            raise ValueError("unknown or method-incompatible semantic fields")
        result = function(**{k: v for k, v in request.items() if k != "method"}).to_dict()
        output = json.dumps(result, sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2) + "\n"
        if args.output == "-":
            sys.stdout.write(output)
        else:
            with Path(args.output).open("w" if args.force else "x", encoding="utf-8", newline="\n") as file:
                file.write(output)
    except (OSError, ValueError, TypeError, OverflowError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
