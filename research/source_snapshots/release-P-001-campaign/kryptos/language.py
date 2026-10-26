"""Explicit-corpus character n-grams, with gaps and provenance preserved.

No language data is bundled. This is a smoothed *joint n-gram* ranking model,
not a probability that a text is a language or a Kryptos solution. Every
complete window has equal weight; short unmasked fragments supply no windows.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from types import MappingProxyType
from typing import Iterable, Mapping


ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
SCHEMA = "kryptos.character-ngram.v1"


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False)


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("JSON numbers must be finite")
    return number


def _reject_constant(value):
    raise ValueError(f"nonstandard JSON constant: {value}")


def _load_json(serialized):
    return json.loads(serialized, object_pairs_hook=_unique_object,
                      parse_float=_finite_float, parse_constant=_reject_constant)


def _nonempty(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")


def _logadd(left, right):
    high, low = max(left, right), min(left, right)
    return high + math.log1p(math.exp(low - high))


def _settings(alphabet, order, alpha, normalization):
    if (not isinstance(alphabet, str) or len(alphabet) < 2
            or len(set(alphabet)) != len(alphabet)):
        raise ValueError("alphabet must contain at least two distinct symbols")
    if type(order) is not int or not 1 <= order <= 8:
        raise ValueError("order must be an integer from 1 to 8")
    try:
        valid_alpha = type(alpha) in (int, float) and math.isfinite(alpha) and alpha > 0
    except OverflowError:
        valid_alpha = False
    if not valid_alpha:
        raise ValueError("alpha must be finite and positive")
    if normalization not in ("identity", "upper-single"):
        raise ValueError("normalization must be identity or upper-single")
    if normalization == "upper-single" and any(c.upper() != c for c in alphabet):
        raise ValueError("upper-single requires an uppercase-stable alphabet")


def _runs(text, alphabet, normalization, excluded_positions=()):
    if not isinstance(text, str):
        raise ValueError("text must be a string")
    supplied_positions = tuple(excluded_positions)
    if any(type(i) is not int or not 0 <= i < len(text) for i in supplied_positions):
        raise ValueError("excluded positions must be zero-based indices inside text")
    excluded = frozenset(supplied_positions)
    runs, current, eligible, unsupported = [], [], [], []
    for position, raw in enumerate(text):
        symbol = raw.upper() if normalization == "upper-single" else raw
        valid = len(symbol) == 1 and symbol in alphabet
        if position not in excluded and valid:
            current.append((position, symbol))
            eligible.append(position)
        else:
            if position not in excluded and not valid:
                unsupported.append(position)
            if current:
                runs.append(current)
                current = []
    if current:
        runs.append(current)
    return runs, tuple(sorted(excluded)), tuple(eligible), tuple(unsupported)


@dataclass(frozen=True)
class CorpusDocument:
    """Caller-supplied text and its source/split identifier; never downloaded."""

    text: str
    source: str
    license: str | None = None

    def __post_init__(self):
        if not isinstance(self.text, str):
            raise ValueError("corpus text must be a string")
        _nonempty(self.source, "source")
        if self.license is not None:
            _nonempty(self.license, "license")


@dataclass(frozen=True)
class CorpusProvenance:
    source: str
    sha256: str
    characters: int
    eligible_characters: int
    windows: int
    license: str | None = None


@dataclass(frozen=True)
class NgramScore:
    model_id: str
    mean_log_probability: float | None
    log_probability_sum: float
    windows: int
    text_length: int
    excluded_positions: tuple[int, ...]
    eligible_positions: tuple[int, ...]
    scored_positions: tuple[int, ...]
    unsupported_positions: tuple[int, ...]

    @property
    def available(self) -> bool:
        return self.windows > 0

    @property
    def layout(self):
        """Exact comparison shape, including gaps rather than coverage alone."""
        return self.text_length, self.excluded_positions, self.eligible_positions

    def to_dict(self):
        result = asdict(self)
        result.update(available=self.available,
                      eligible_characters=len(self.eligible_positions),
                      scored_characters=len(self.scored_positions))
        return result


@dataclass(frozen=True)
class CharacterNgramModel:
    label: str
    alphabet: str
    order: int
    alpha: float
    normalization: str
    counts: Mapping[str, int]
    corpora: tuple[CorpusProvenance, ...]
    created_utc: str
    _model_id: str = field(init=False, repr=False, compare=False)
    _log_probabilities: Mapping[str, float] = field(init=False, repr=False, compare=False)
    _unknown_log_probability: float = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        _nonempty(self.label, "label")
        _settings(self.alphabet, self.order, self.alpha, self.normalization)
        _nonempty(self.created_utc, "created_utc")
        try:
            created = datetime.fromisoformat(self.created_utc)
        except ValueError as error:
            raise ValueError("created_utc must be an ISO UTC timestamp") from error
        if created.utcoffset() != timedelta(0):
            raise ValueError("created_utc must include a UTC timezone")
        if not isinstance(self.counts, Mapping):
            raise ValueError("counts must be a mapping")
        counts = dict(self.counts)
        if not counts or any(
            not isinstance(k, str) or len(k) != self.order
            or any(c not in self.alphabet for c in k)
            or type(v) is not int or v <= 0 for k, v in counts.items()
        ):
            raise ValueError("counts must be positive integers for valid n-grams")
        corpora = tuple(self.corpora)
        if not corpora or any(not isinstance(p, CorpusProvenance) for p in corpora):
            raise ValueError("corpus provenance is required")
        for p in corpora:
            _nonempty(p.source, "corpus source")
            if (not isinstance(p.sha256, str) or len(p.sha256) != 64
                    or any(c not in "0123456789abcdef" for c in p.sha256)):
                raise ValueError("invalid corpus sha256")
            if (any(type(v) is not int or v < 0 for v in
                    (p.characters, p.eligible_characters, p.windows))
                    or p.eligible_characters > p.characters
                    or p.windows > max(0, p.eligible_characters - self.order + 1)):
                raise ValueError("invalid corpus coverage")
            if p.license is not None:
                _nonempty(p.license, "corpus license")
        if len({p.source for p in corpora}) != len(corpora):
            raise ValueError("corpus source identifiers must be distinct")
        if sum(p.windows for p in corpora) != sum(counts.values()):
            raise ValueError("corpus window totals disagree with counts")
        object.__setattr__(self, "counts", MappingProxyType(counts))
        object.__setattr__(self, "corpora", corpora)
        object.__setattr__(self, "_model_id", _digest(_canonical(self._payload())))
        log_alpha = math.log(self.alpha)
        log_denominator = _logadd(math.log(sum(counts.values())),
                                  log_alpha + self.order * math.log(len(self.alphabet)))
        probabilities = {gram: _logadd(math.log(count), log_alpha) - log_denominator
                         for gram, count in counts.items()}
        object.__setattr__(self, "_log_probabilities", MappingProxyType(probabilities))
        object.__setattr__(self, "_unknown_log_probability", log_alpha - log_denominator)

    def _payload(self):
        return dict(schema=SCHEMA, label=self.label, alphabet=self.alphabet,
                    order=self.order, alpha=self.alpha,
                    normalization=self.normalization, counts=dict(self.counts),
                    corpora=[asdict(p) for p in self.corpora],
                    created_utc=self.created_utc)

    @property
    def model_id(self):
        return self._model_id

    def to_dict(self):
        result = self._payload()
        result["model_id"] = self.model_id
        return result

    def to_json(self):
        """Serialize counts/settings/provenance, without the corpus text."""
        return _canonical(self.to_dict())

    @classmethod
    def from_json(cls, serialized: str):
        value = _load_json(serialized)
        if not isinstance(value, dict):
            raise ValueError("model JSON must be an object")
        expected = {"schema", "model_id", "label", "alphabet", "order", "alpha",
                    "normalization", "counts", "corpora", "created_utc"}
        if set(value) != expected or value["schema"] != SCHEMA:
            raise ValueError("unsupported model schema or fields")
        model_id = value.pop("model_id")
        if model_id != _digest(_canonical(value)):
            raise ValueError("model content hash mismatch")
        value.pop("schema")
        try:
            value["corpora"] = tuple(CorpusProvenance(**p) for p in value["corpora"])
            return cls(**value)
        except (TypeError, KeyError) as error:
            raise ValueError("invalid model structure") from error

    def score(self, text: str, excluded_positions=()) -> NgramScore:
        runs, excluded, eligible, unsupported = _runs(
            text, self.alphabet, self.normalization, excluded_positions)
        total, windows, scored = 0.0, 0, set()
        for run in runs:
            symbols = "".join(c for _, c in run)
            for start in range(len(run) - self.order + 1):
                gram = symbols[start:start + self.order]
                total += self._log_probabilities.get(gram, self._unknown_log_probability)
                windows += 1
                scored.update(i for i, _ in run[start:start + self.order])
        return NgramScore(self.model_id, total / windows if windows else None,
                          total, windows, len(text), excluded, eligible,
                          tuple(sorted(scored)), unsupported)


def train_ngram_model(documents: Iterable[CorpusDocument], *, label: str,
                      order: int = 3, alphabet: str = ALPHABET,
                      alpha: float = 0.1,
                      normalization: str = "upper-single") -> CharacterNgramModel:
    """Train on caller-supplied documents; never join documents or invalid symbols.

    ``upper-single`` uppercases one original character only when the result is
    one alphabet symbol. Thus sharp-s expanding to SS is a boundary, not a new
    pair. Identity normalization permits an explicitly selected Unicode alphabet.
    """
    _settings(alphabet, order, alpha, normalization)
    counts, provenance = Counter(), []
    for document in documents:
        if not isinstance(document, CorpusDocument):
            raise ValueError("documents must contain CorpusDocument records")
        runs, _, eligible, _ = _runs(document.text, alphabet, normalization)
        windows = 0
        for run in runs:
            text = "".join(c for _, c in run)
            counts.update(text[i:i + order] for i in range(len(text) - order + 1))
            windows += max(0, len(text) - order + 1)
        provenance.append(CorpusProvenance(
            document.source, _digest(document.text), len(document.text), len(eligible),
            windows, document.license))
    return CharacterNgramModel(label, alphabet, order, alpha, normalization, counts,
                               tuple(provenance), datetime.now(timezone.utc).isoformat())


@dataclass(frozen=True)
class ControlAssessment:
    score: NgramScore
    standardized_score: float | None
    smoothed_control_exceedance: float
    control_count: int
    exact_training_duplicate: bool
    exact_control_duplicate: bool

    def to_dict(self):
        value = asdict(self)
        value["score"] = self.score.to_dict()
        return value


@dataclass(frozen=True)
class ControlCalibration:
    """A model-specific reference distribution, not language/solution confidence."""

    model_id: str
    description: str
    layout: tuple
    scores: tuple[float, ...]
    controls: tuple[CorpusProvenance, ...]
    mean: float
    standard_deviation: float

    def assess(self, model: CharacterNgramModel, text: str,
               excluded_positions=()) -> ControlAssessment:
        if model.model_id != self.model_id:
            raise ValueError("calibration belongs to a different model")
        score = model.score(text, excluded_positions)
        if score.layout != self.layout or not score.available:
            raise ValueError("candidate must have the calibration's exact mask and symbol layout")
        value = score.mean_log_probability
        z = ((value - self.mean) / self.standard_deviation
             if self.standard_deviation else None)
        tail = (1 + sum(control >= value for control in self.scores)) / (len(self.scores) + 1)
        digest = _digest(text)
        return ControlAssessment(score, z, tail, len(self.scores),
                                 digest in {p.sha256 for p in model.corpora},
                                 digest in {p.sha256 for p in self.controls})

    def to_dict(self):
        return dict(schema="kryptos.ngram-control-calibration.v1", **asdict(self))


def calibrate_controls(model: CharacterNgramModel,
                       controls: Iterable[CorpusDocument], *, description: str,
                       excluded_positions=()) -> ControlCalibration:
    """Score at least two distinct, explicit same-layout reference texts.

    Use the same held-out controls/mask and compatible settings when inspecting
    several models, with a separate calibration for each. No winner is inferred.
    Exact training-document/source overlap is rejected; partial overlap and
    honest splitting remain the caller's responsibility. Search-selected output
    needs controls that repeat the whole selection procedure, not just this score.
    """
    _nonempty(description, "control description")
    mask = tuple(excluded_positions)
    training_hashes = {p.sha256 for p in model.corpora}
    training_sources = {p.source for p in model.corpora}
    scores, provenance, layout, hashes, sources = [], [], None, set(), set()
    for document in controls:
        if not isinstance(document, CorpusDocument):
            raise ValueError("controls must contain CorpusDocument records")
        digest = _digest(document.text)
        if digest in training_hashes or document.source in training_sources:
            raise ValueError("control duplicates a training document or source identifier")
        if digest in hashes or document.source in sources:
            raise ValueError("control documents and source identifiers must be distinct")
        score = model.score(document.text, mask)
        if not score.available:
            raise ValueError("every control must supply at least one n-gram")
        if layout is not None and score.layout != layout:
            raise ValueError("controls must have identical masks and symbol layouts")
        layout = score.layout
        scores.append(score.mean_log_probability)
        provenance.append(CorpusProvenance(document.source, digest, len(document.text),
                                           len(score.eligible_positions), score.windows,
                                           document.license))
        hashes.add(digest)
        sources.add(document.source)
    if len(scores) < 2:
        raise ValueError("at least two distinct controls are required")
    mean = math.fsum(scores) / len(scores)
    deviation = (math.sqrt(math.fsum((s - mean) ** 2 for s in scores) / len(scores))
                 if len(set(scores)) > 1 else 0.0)
    return ControlCalibration(model.model_id, description, layout, tuple(scores),
                              tuple(provenance), mean, deviation)


def _documents(value):
    if not isinstance(value, list):
        raise ValueError("documents must be a JSON array")
    try:
        return [CorpusDocument(**item) for item in value]
    except TypeError as error:
        raise ValueError("each document requires text, source, and optional license") from error


def main(argv=None):
    """Small explicit-input CLI; output files are exclusive unless --force is set."""
    import argparse
    from pathlib import Path
    import sys

    parser = argparse.ArgumentParser(
        description="Train or score explicit-corpus character n-grams. No corpus is bundled.")
    commands = parser.add_subparsers(dest="command", required=True)
    train = commands.add_parser("train", help="train from JSON documents or explicit UTF-8 files")
    inputs = train.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--input", help="JSON object with documents, label, and model settings")
    inputs.add_argument("--corpus", action="append", help="explicit UTF-8 corpus file; repeatable")
    train.add_argument("--label", help="required model label with --corpus")
    train.add_argument("--license", help="optional provenance note for each --corpus file")
    train.add_argument("--order", type=int)
    train.add_argument("--alphabet")
    train.add_argument("--alpha", type=float)
    train.add_argument("--normalization", choices=("identity", "upper-single"))
    score_command = commands.add_parser("score", help="score JSON text/mask and optional explicit controls")
    score_command.add_argument("--model", required=True, help="saved model JSON")
    score_command.add_argument("--input", required=True,
                               help="JSON with text, optional excluded_positions, controls, control_description")
    for command in (train, score_command):
        command.add_argument("--output", default="-", help="new JSON file or - for stdout (default)")
        command.add_argument("--force", action="store_true", help="allow replacing the output file")
    args = parser.parse_args(argv)

    def read_json(path):
        return _load_json(Path(path).read_bytes().decode("utf-8-sig"))

    try:
        if args.command == "train":
            options = {k: getattr(args, k) for k in
                       ("label", "order", "alphabet", "alpha", "normalization")
                       if getattr(args, k) is not None}
            if args.input:
                if options or args.license is not None:
                    raise ValueError("model settings for --input must be inside that JSON object")
                request = read_json(args.input)
                if not isinstance(request, dict):
                    raise ValueError("training input must be a JSON object")
                allowed = {"documents", "label", "order", "alphabet", "alpha", "normalization"}
                if not {"documents", "label"} <= set(request) or set(request) - allowed:
                    raise ValueError("training JSON requires documents and label; unknown fields are rejected")
                options = {k: v for k, v in request.items() if k != "documents"}
                documents = _documents(request["documents"])
            else:
                if "label" not in options:
                    raise ValueError("--label is required with --corpus")
                documents = [CorpusDocument(Path(path).read_bytes().decode("utf-8"),
                                            str(Path(path).resolve()), args.license)
                             for path in args.corpus]
            result = train_ngram_model(documents, **options).to_dict()
        else:
            model = CharacterNgramModel.from_json(Path(args.model).read_bytes().decode("utf-8-sig"))
            request = read_json(args.input)
            allowed = {"text", "excluded_positions", "controls", "control_description"}
            if (not isinstance(request, dict) or "text" not in request
                    or set(request) - allowed):
                raise ValueError("score JSON requires text; unknown fields are rejected")
            mask = request.get("excluded_positions", ())
            scored = model.score(request["text"], mask)
            result = dict(schema="kryptos.ngram-score.v1", model_id=model.model_id,
                          model_label=model.label, input_sha256=_digest(request["text"]),
                          request_sha256=_digest(_canonical(request)), score=scored.to_dict())
            if "controls" in request:
                calibration = calibrate_controls(
                    model, _documents(request["controls"]),
                    description=request.get("control_description", ""), excluded_positions=mask)
                result["calibration"] = calibration.to_dict()
                result["assessment"] = calibration.assess(model, request["text"], mask).to_dict()
            elif "control_description" in request:
                raise ValueError("control_description requires controls")
        output = _canonical(result) + "\n"
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
