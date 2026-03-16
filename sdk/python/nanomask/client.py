from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

DEFAULT_PROXY_BASE_URL = os.getenv("NANOMASK_BASE_URL", "http://127.0.0.1:8081/v1")
DEFAULT_ENTITY_HEADER = "X-ZPG-Entities"


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    status_code: int | None
    url: str
    error: str | None = None


def normalize_base_url(base_url: str | None = None) -> str:
    raw = (base_url or DEFAULT_PROXY_BASE_URL).strip()
    if not raw:
        raw = DEFAULT_PROXY_BASE_URL

    parts = urlsplit(raw)
    path = parts.path.rstrip("/")
    if not path.endswith("/v1"):
        path = f"{path}/v1" if path else "/v1"
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))


def healthcheck_url(base_url: str | None = None, path: str = "/healthz") -> str:
    normalized = urlsplit(normalize_base_url(base_url))
    probe_path = path if path.startswith("/") else f"/{path}"
    prefix = normalized.path[:-3] if normalized.path.endswith("/v1") else normalized.path
    final_path = f"{prefix.rstrip('/')}{probe_path}" if prefix else probe_path
    return urlunsplit((normalized.scheme, normalized.netloc, final_path, "", normalized.fragment))


def entity_headers(
    entities: str | Iterable[str] | None,
    header_name: str = DEFAULT_ENTITY_HEADER,
) -> dict[str, str]:
    if entities is None:
        return {}
    if isinstance(entities, str):
        value = entities.strip()
        return {header_name: value} if value else {}

    cleaned = [entity.strip() for entity in entities if entity and entity.strip()]
    if not cleaned:
        return {}
    return {header_name: ", ".join(cleaned)}


def _merged_headers(
    default_headers: Mapping[str, str] | None,
    entities: str | Iterable[str] | None,
    header_name: str,
) -> dict[str, str]:
    headers = dict(default_headers or {})
    headers.update(entity_headers(entities, header_name=header_name))
    return headers


def _load_openai_client(async_client: bool) -> Any:
    try:
        if async_client:
            from openai import AsyncOpenAI as openai_client
        else:
            from openai import OpenAI as openai_client
    except ImportError as exc:
        raise RuntimeError(
            "Install the official 'openai' package to use NanoMask SDK wrappers."
        ) from exc
    return openai_client


def OpenAI(
    *,
    base_url: str | None = None,
    entities: str | Iterable[str] | None = None,
    header_name: str = DEFAULT_ENTITY_HEADER,
    default_headers: Mapping[str, str] | None = None,
    client_cls: Any | None = None,
    **kwargs: Any,
) -> Any:
    client_factory = client_cls or _load_openai_client(async_client=False)
    headers = _merged_headers(default_headers, entities, header_name)
    return client_factory(
        base_url=normalize_base_url(base_url),
        default_headers=headers or None,
        **kwargs,
    )


def AsyncOpenAI(
    *,
    base_url: str | None = None,
    entities: str | Iterable[str] | None = None,
    header_name: str = DEFAULT_ENTITY_HEADER,
    default_headers: Mapping[str, str] | None = None,
    client_cls: Any | None = None,
    **kwargs: Any,
) -> Any:
    client_factory = client_cls or _load_openai_client(async_client=True)
    headers = _merged_headers(default_headers, entities, header_name)
    return client_factory(
        base_url=normalize_base_url(base_url),
        default_headers=headers or None,
        **kwargs,
    )


def verify(
    *,
    base_url: str | None = None,
    path: str = "/healthz",
    expected_status: int = 200,
    timeout: float = 2.0,
) -> VerifyResult:
    url = healthcheck_url(base_url, path=path)
    request = Request(url, headers={"Accept": "application/json"}, method="GET")

    try:
        with urlopen(request, timeout=timeout) as response:
            status_code = getattr(response, "status", response.getcode())
            return VerifyResult(
                ok=status_code == expected_status,
                status_code=status_code,
                url=url,
                error=None if status_code == expected_status else f"unexpected status {status_code}",
            )
    except HTTPError as exc:
        return VerifyResult(
            ok=False,
            status_code=exc.code,
            url=url,
            error=f"unexpected status {exc.code}",
        )
    except URLError as exc:
        return VerifyResult(
            ok=False,
            status_code=None,
            url=url,
            error=str(exc.reason),
        )
