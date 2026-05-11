from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nanomask import OpenAI, entity_headers, healthcheck_url, normalize_base_url, with_entities


class FakeClient:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class NanoMaskSdkTests(unittest.TestCase):
    def test_normalize_base_url_adds_v1(self) -> None:
        self.assertEqual("http://127.0.0.1:8081/v1", normalize_base_url("http://127.0.0.1:8081"))

    def test_healthcheck_url_strips_v1(self) -> None:
        self.assertEqual("http://127.0.0.1:8081/healthz", healthcheck_url("http://127.0.0.1:8081/v1"))

    def test_entity_headers_joins_names(self) -> None:
        self.assertEqual(
            {"X-NanoMask-Entities": "Jane Doe, ACME"},
            entity_headers(["Jane Doe", "ACME"]),
        )

    def test_openai_factory_sets_base_url_and_headers(self) -> None:
        client = OpenAI(
            client_cls=FakeClient,
            api_key="replace-me",
            entities=["Jane Doe"],
            default_headers={"x-trace-id": "abc"},
        )
        self.assertEqual("http://127.0.0.1:8081/v1", client.kwargs["base_url"])
        self.assertEqual("abc", client.kwargs["default_headers"]["x-trace-id"])
        self.assertEqual("Jane Doe", client.kwargs["default_headers"]["X-NanoMask-Entities"])

    def test_with_entities_sets_per_request_headers(self) -> None:
        options = with_entities({"extra_headers": {"x-trace-id": "abc"}}, ["Jane Doe"])
        self.assertEqual("abc", options["extra_headers"]["x-trace-id"])
        self.assertEqual("Jane Doe", options["extra_headers"]["X-NanoMask-Entities"])


if __name__ == "__main__":
    unittest.main()
