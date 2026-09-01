#!/usr/bin/env python3
"""Audit published npm tarballs without extracting or executing package code.

Input may be a text file of package names (resolves latest versions) or a prior
results JSON file (reuses its exact versioned tarball URLs as a lock file).
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import io
import json
import sys
import tarfile
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path, PurePosixPath

# Make `driftward` importable when this script is run straight from a clone
# (`python3 research/.../audit.py …`) without `pip install`.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from driftward import scanner


GENERATED_DIRS = {"dist", "build", "out", "bundle", "bundles"}
NON_RUNTIME_DIRS = {
    "test", "tests", "__tests__", "spec", "specs", "fixtures",
    "examples", "example", "e2e", "node_modules",
}


def registry_latest_url(name: str) -> str:
    return "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="") + "/latest"


def path_parts(name: str) -> tuple[str, ...]:
    relative = name.removeprefix("package/").strip("/").lower()
    return tuple(part for part in PurePosixPath(relative).parts if part not in ("", "."))


def is_generated(parts: tuple[str, ...], name: str) -> bool:
    return bool(set(parts[:-1]) & GENERATED_DIRS) or ".min." in name.lower()


def is_non_runtime(parts: tuple[str, ...]) -> bool:
    return bool(set(parts[:-1]) & NON_RUNTIME_DIRS)


def fetch_json(url: str) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "driftward-corpus-audit/0.1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def fetch_bytes(url: str, max_bytes: int) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "driftward-corpus-audit/0.1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        declared = response.headers.get("Content-Length")
        if declared and int(declared) > max_bytes:
            raise ValueError(f"tarball too large: {declared} bytes")
        payload = response.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise ValueError(f"tarball too large: >{max_bytes} bytes")
    return payload


def verify_integrity(payload: bytes, integrity: str | None) -> bool | None:
    if not integrity:
        return None
    algorithm, separator, encoded = integrity.partition("-")
    if not separator or algorithm not in hashlib.algorithms_available:
        return None
    expected = base64.b64decode(encoded)
    actual = hashlib.new(algorithm, payload).digest()
    if actual != expected:
        raise ValueError("tarball integrity mismatch")
    return True


def resolve(spec: str | dict) -> dict:
    if isinstance(spec, dict) and spec.get("tarball"):
        return {
            "name": str(spec["name"]),
            "version": spec.get("version"),
            "description": spec.get("description", ""),
            "tarball": str(spec["tarball"]),
            "integrity": spec.get("integrity"),
        }
    name = str(spec["name"] if isinstance(spec, dict) else spec)
    metadata = fetch_json(registry_latest_url(name))
    return {
        "name": name,
        "version": metadata.get("version"),
        "description": metadata.get("description", ""),
        "tarball": metadata["dist"]["tarball"],
        "integrity": metadata.get("dist", {}).get("integrity"),
    }


def audit(spec: str | dict, max_bytes: int) -> dict:
    identity = str(spec.get("name") if isinstance(spec, dict) else spec)
    result = {"name": identity}
    try:
        package = resolve(spec)
        payload = fetch_bytes(package["tarball"], max_bytes)
        integrity_verified = verify_integrity(payload, package.get("integrity"))

        eligible_code: list[str] = []
        runtime_code: list[str] = []
        generated_code: list[str] = []
        source_maps = 0
        network: set[str] = set()
        url_hosts: set[str] = set()
        credential_hits = 0
        subprocess_hits = 0
        injection: set[str] = set()
        raw_tokens: Counter[str] = Counter()

        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                relative = member.name.removeprefix("package/")
                parts = path_parts(member.name)
                suffix = PurePosixPath(relative).suffix.lower()
                if suffix == ".map":
                    source_maps += 1
                if suffix in scanner.CODE_EXTS and not is_non_runtime(parts):
                    runtime_code.append(relative)
                    if is_generated(parts, relative):
                        generated_code.append(relative)

                posix = "/" + relative.lower()
                skipped = any(marker in posix for marker in scanner.SKIP_MARKERS)
                if suffix in scanner.CODE_EXTS and not skipped:
                    eligible_code.append(relative)

                inspect_with_scanner = (
                    suffix in scanner.TEXT_EXTS
                    and not skipped
                    and member.size <= scanner.MAX_FILE_BYTES
                )
                inspect_raw_example = (
                    package["name"] == "malicious-mcp-server"
                    and suffix in scanner.CODE_EXTS
                    and member.size <= scanner.MAX_FILE_BYTES
                )
                if not inspect_with_scanner and not inspect_raw_example:
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                text = extracted.read(scanner.MAX_FILE_BYTES + 1).decode("utf-8", errors="replace")

                if inspect_raw_example:
                    raw_tokens["exec"] += text.count("exec")
                    raw_tokens["eval("] += text.count("eval(")
                    raw_tokens["base64"] += text.lower().count("base64")
                    raw_tokens["raw.githubusercontent.com"] += text.count("raw.githubusercontent.com")
                if not inspect_with_scanner:
                    continue

                for pattern, label in scanner.INJECTION_PATTERNS:
                    if pattern.search(text):
                        injection.add(label)
                if suffix not in scanner.CODE_EXTS:
                    continue
                for pattern, label in scanner.NETWORK_PATTERNS:
                    for match in pattern.finditer(text):
                        if label == "url-literal":
                            host = scanner._host_of(match.group(0))
                            if host:
                                url_hosts.add(host)
                        else:
                            network.add(label)
                for pattern in scanner.CREDENTIAL_PATTERNS:
                    credential_hits += len(pattern.findall(text))
                for pattern in scanner.SUBPROCESS_PATTERNS:
                    subprocess_hits += len(pattern.findall(text))

        result.update({
            **package,
            "integrity_verified": integrity_verified,
            "tarball_bytes": len(payload),
            "tarball_sha256": hashlib.sha256(payload).hexdigest(),
            "runtime_code_files": len(runtime_code),
            "generated_code_files": len(generated_code),
            "eligible_code_files": len(eligible_code),
            "scanner_blind_to_runtime_code": bool(runtime_code and not eligible_code),
            "all_runtime_code_in_generated_dirs": bool(
                runtime_code and len(runtime_code) == len(generated_code)
            ),
            "source_maps": source_maps,
            "network": sorted(network),
            "url_hosts": sorted(url_hosts),
            "credential_hits": credential_hits,
            "subprocess_hits": subprocess_hits,
            "injection": sorted(injection),
            "raw_tokens": dict(raw_tokens),
        })
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def load_specs(path: Path) -> list[str | dict]:
    if path.suffix.lower() == ".json":
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, list):
            raise ValueError("JSON input must be a list")
        return value
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def summarize(results: list[dict]) -> dict:
    valid = [result for result in results if "error" not in result]
    return {
        "requested": len(results),
        "audited": len(valid),
        "errors": len(results) - len(valid),
        "scanner_blind": sum(result["scanner_blind_to_runtime_code"] for result in valid),
        "blind_with_source_maps": sum(
            result["scanner_blind_to_runtime_code"] and bool(result["source_maps"])
            for result in valid
        ),
        "blind_without_source_maps": sum(
            result["scanner_blind_to_runtime_code"] and not result["source_maps"]
            for result in valid
        ),
        "with_credential_refs": sum(bool(result["credential_hits"]) for result in valid),
        "with_injection": sum(bool(result["injection"]) for result in valid),
        "with_subprocess": sum(bool(result["subprocess_hits"]) for result in valid),
        "with_network_signal": sum(
            bool(result["network"] or result["url_hosts"]) for result in valid
        ),
        "with_url_hosts": sum(bool(result["url_hosts"]) for result in valid),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path, help="packages.txt or prior results.json lock")
    parser.add_argument("output", type=Path, help="where to write raw results JSON")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--max-tarball-mb", type=int, default=100)
    args = parser.parse_args()

    specs = load_specs(args.input)
    results_by_name: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(audit, spec, args.max_tarball_mb * 1_000_000): str(
                spec.get("name") if isinstance(spec, dict) else spec
            )
            for spec in specs
        }
        for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
            result = future.result()
            results_by_name[result["name"]] = result
            state = "error" if "error" in result else "ok"
            print(f"[{index}/{len(specs)}] {result['name']}: {state}", file=sys.stderr, flush=True)

    names = [str(spec.get("name") if isinstance(spec, dict) else spec) for spec in specs]
    results = [results_by_name[name] for name in names]
    args.output.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summarize(results), indent=2, sort_keys=True))
    return 0 if all("error" not in result for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
