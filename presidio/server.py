"""Local Presidio Analyzer server for piip (English + Japanese).

Speaks the same REST API as the official presidio-analyzer container
(GET /health, GET /supportedentities, POST /analyze), plus
GET /supportedlanguages, so piip works with either. Text never leaves the
machine: the server binds to 127.0.0.1 by default.

    uv run --project presidio presidio/server.py [--host 127.0.0.1] [--port 5002]

Environment:
    PIIP_PRESIDIO_LANGS   comma-separated languages to load (default: en,ja)
    PIIP_SPACY_EN         spaCy model for English (default: en_core_web_md)
    PIIP_SPACY_JA         spaCy model for Japanese (default: ja_core_news_md)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import (
    CreditCardRecognizer,
    EmailRecognizer,
    IbanRecognizer,
    IpRecognizer,
    PhoneRecognizer,
)

MODELS = {
    "en": os.environ.get("PIIP_SPACY_EN", "en_core_web_md"),
    "ja": os.environ.get("PIIP_SPACY_JA", "ja_core_news_md"),
}

# spaCy labels (OntoNotes style, also used by ja_core_news_*) -> Presidio.
ENTITY_MAPPING = {
    "PERSON": "PERSON",
    "PER": "PERSON",
    "GPE": "LOCATION",
    "LOC": "LOCATION",
    "FAC": "LOCATION",
    "ORG": "ORGANIZATION",
    "NORP": "NRP",
    "DATE": "DATE_TIME",
    "TIME": "DATE_TIME",
}

LABELS_TO_IGNORE = [
    "CARDINAL", "ORDINAL", "QUANTITY", "MONEY", "PERCENT", "PRODUCT", "EVENT",
    "WORK_OF_ART", "LAW", "LANGUAGE", "MOVEMENT", "PET_NAME", "PHONE", "TITLE_AFFIX",
]


def build_analyzer(languages: list[str]) -> AnalyzerEngine:
    nlp_engine = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": lang, "model_name": MODELS[lang]} for lang in languages],
            "ner_model_configuration": {
                "model_to_presidio_entity_mapping": ENTITY_MAPPING,
                "labels_to_ignore": LABELS_TO_IGNORE,
                "low_score_entity_names": ["ORG", "ORGANIZATION"],
                "low_confidence_score_multiplier": 0.4,
            },
        }
    ).create_engine()

    registry = RecognizerRegistry(supported_languages=languages)
    registry.load_predefined_recognizers(nlp_engine=nlp_engine, languages=languages)

    # Presidio's pattern recognizers are English-only by default; register
    # the language-independent ones for Japanese text too.
    if "ja" in languages:
        for recognizer in (
            EmailRecognizer(supported_language="ja"),
            CreditCardRecognizer(supported_language="ja"),
            IpRecognizer(supported_language="ja"),
            IbanRecognizer(supported_language="ja"),
            PhoneRecognizer(supported_language="ja", supported_regions=("JP", "US", "UK")),
        ):
            registry.add_recognizer(recognizer)

    return AnalyzerEngine(nlp_engine=nlp_engine, registry=registry, supported_languages=languages)


class Handler(BaseHTTPRequestHandler):
    analyzer: AnalyzerEngine
    languages: list[str]
    lock = threading.Lock()

    def log_message(self, fmt, *args):  # Keep request text out of logs.
        logging.debug("%s %s", self.command, self.path)

    def send_json(self, status: int, payload) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/health":
            body = b"Presidio Analyzer service is up"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif url.path == "/supportedlanguages":
            self.send_json(200, self.languages)
        elif url.path == "/supportedentities":
            lang = parse_qs(url.query).get("language", ["en"])[0]
            if lang not in self.languages:
                self.send_json(400, {"error": f"unsupported language {lang}"})
                return
            self.send_json(200, sorted(self.analyzer.get_supported_entities(language=lang)))
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        if urlparse(self.path).path != "/analyze":
            self.send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(length) or b"{}")
            text = req["text"]
            language = req.get("language", "en")
            if language not in self.languages:
                self.send_json(400, {"error": f"unsupported language {language}; loaded: {self.languages}"})
                return
            with self.lock:
                results = self.analyzer.analyze(
                    text=text,
                    language=language,
                    entities=req.get("entities") or None,
                    score_threshold=req.get("score_threshold"),
                )
            self.send_json(200, [r.to_dict() for r in results])
        except (KeyError, ValueError) as e:
            self.send_json(400, {"error": f"bad request: {e}"})
        except Exception as e:  # noqa: BLE001
            logging.exception("analyze failed")
            self.send_json(500, {"error": str(e)})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default=os.environ.get("PIIP_PRESIDIO_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PIIP_PRESIDIO_PORT", "5002")))
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    languages = [l.strip() for l in os.environ.get("PIIP_PRESIDIO_LANGS", "en,ja").split(",") if l.strip()]
    unknown = [l for l in languages if l not in MODELS]
    if unknown:
        raise SystemExit(f"no spaCy model configured for: {unknown}")

    logging.info("loading models: %s", {l: MODELS[l] for l in languages})
    Handler.analyzer = build_analyzer(languages)
    Handler.languages = languages
    Handler.analyzer.analyze(text="warm up", language=languages[0])

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    logging.info("Presidio Analyzer listening on http://%s:%d (%s)", args.host, args.port, ",".join(languages))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
