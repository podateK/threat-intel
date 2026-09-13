from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiohttp

from config import settings
from models.ioc import IOCCreate, IOCType, IOCSeverity

logger = logging.getLogger(__name__)


def load_feeds() -> list[dict]:
    try:
        with open(settings.FEEDS_PATH) as f:
            data = json.load(f)
        return data.get("feeds", [])
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning("Failed to load feeds config: %s", e)
        return []


async def fetch_feed(url: str, timeout: int = 60) -> Optional[str]:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                if resp.status == 200:
                    return await resp.text()
                logger.warning("Feed fetch failed %d: %s", resp.status, url)
                return None
    except Exception as e:
        logger.warning("Feed fetch error for %s: %s", url, e)
        return None


def parse_csv_feed(content: str, column_map: Optional[dict] = None) -> list[dict]:
    import csv
    import io
    if column_map is None:
        column_map = {"value": 0, "type": 1, "severity": 2, "tags": 3, "source": 4}

    reader = csv.reader(io.StringIO(content))
    rows = list(reader)
    if not rows:
        return []

    header = rows[0]
    records = []
    for row in rows[1:]:
        if len(row) <= column_map.get("value", 0):
            continue
        record = {}
        for field, idx in column_map.items():
            if idx < len(row):
                record[field] = row[idx].strip()
        records.append(record)
    return records


def parse_stix_bundle(content: str) -> list[dict]:
    try:
        bundle = json.loads(content)
    except json.JSONDecodeError:
        logger.warning("Failed to parse STIX bundle as JSON")
        return []

    objects = bundle.get("objects", [])
    iocs = []

    for obj in objects:
        obj_type = obj.get("type", "")

        if obj_type == "indicator":
            pattern = obj.get("pattern", "")
            labels = obj.get("labels", [])
            name = obj.get("name", "")

            ioc_data = _extract_ioc_from_stix_pattern(pattern)
            if ioc_data:
                ioc_data["tags"] = labels
                ioc_data["source"] = f"stix:{name}" if name else "stix"
                iocs.append(ioc_data)

        elif obj_type == "malware":
            name = obj.get("name", "")
            labels = obj.get("labels", [])
            iocs.append({
                "value": name,
                "type": "domain",
                "severity": "medium",
                "tags": labels + ["malware"],
                "source": "stix:malware",
            })

    return iocs


def _extract_ioc_from_stix_pattern(pattern: str) -> Optional[dict]:
    import re

    ip_match = re.search(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
    if ip_match:
        return {"value": ip_match.group(1), "type": "ip", "severity": "medium"}

    domain_match = re.search(r"domain-name:value\s*=\s*'([^']+)'", pattern)
    if domain_match:
        return {"value": domain_match.group(1), "type": "domain", "severity": "medium"}

    url_match = re.search(r"url:value\s*=\s*'([^']+)'", pattern)
    if url_match:
        return {"value": url_match.group(1), "type": "url", "severity": "medium"}

    hash_match = re.search(r"file:hashes\.'(?:MD5|SHA-1|SHA-256)'\s*=\s*'([a-fA-F0-9]+)'", pattern)
    if hash_match:
        h = hash_match.group(1)
        length = len(h)
        if length == 32:
            t = "hash_md5"
        elif length == 40:
            t = "hash_sha1"
        elif length == 64:
            t = "hash_sha256"
        else:
            t = "hash_sha256"
        return {"value": h, "type": t, "severity": "medium"}

    email_match = re.search(r"email-addr:value\s*=\s*'([^']+)'", pattern)
    if email_match:
        return {"value": email_match.group(1), "type": "email", "severity": "medium"}

    return None


def parse_json_feed(content: str) -> list[dict]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    if isinstance(data, list):
        raw = data
    elif isinstance(data, dict):
        raw = data.get("data", data.get("ioc_list", data.get("indicators", [])))
        if not isinstance(raw, list):
            raw = [data]
    else:
        return []

    iocs = []
    for item in raw:
        value = item.get("value") or item.get("indicator") or item.get("ioc") or item.get("ip") or item.get("domain")
        if not value:
            continue
        ioc_type = item.get("type") or item.get("indicator_type") or "ip"
        severity = item.get("severity", "medium")
        tags = item.get("tags", item.get("labels", []))
        source = item.get("source", "feed")

        iocs.append({
            "value": str(value).strip(),
            "type": _normalize_feed_type(ioc_type),
            "severity": severity,
            "tags": tags if isinstance(tags, list) else [],
            "source": source,
        })

    return iocs


def _normalize_feed_type(raw: str) -> str:
    mapping = {
        "ip": "ip",
        "ipv4": "ip",
        "ipv6": "ip",
        "domain": "domain",
        "hostname": "domain",
        "hash": "hash_sha256",
        "md5": "hash_md5",
        "sha1": "hash_sha1",
        "sha256": "hash_sha256",
        "url": "url",
        "email": "email",
        "addr": "ip",
    }
    return mapping.get(raw.lower().strip(), "ip")


def _normalize_severity(raw: str) -> IOCSeverity:
    mapping = {
        "info": IOCSeverity.INFO,
        "low": IOCSeverity.LOW,
        "medium": IOCSeverity.MEDIUM,
        "high": IOCSeverity.HIGH,
        "critical": IOCSeverity.CRITICAL,
    }
    return mapping.get(raw.lower().strip(), IOCSeverity.MEDIUM)


def _normalize_ioc_type(raw: str) -> IOCType:
    mapping = {
        "ip": IOCType.IP,
        "ipv4": IOCType.IP,
        "ipv6": IOCType.IP,
        "domain": IOCType.DOMAIN,
        "hash_md5": IOCType.HASH_MD5,
        "hash_sha1": IOCType.HASH_SHA1,
        "hash_sha256": IOCType.HASH_SHA256,
        "url": IOCType.URL,
        "email": IOCType.EMAIL,
    }
    return mapping.get(raw.lower().strip(), IOCType.IP)


def parse_feed(feed_url: str, feed_format: str = "auto") -> list[IOCCreate]:
    content = asyncio.get_event_loop().run_until_complete(fetch_feed(feed_url)) if asyncio.get_event_loop().is_running() else None
    if content is None:
        return []

    if feed_format == "auto":
        if '"type"' in content and '"objects"' in content:
            feed_format = "stix"
        elif content.strip().startswith("[") or content.strip().startswith("{"):
            feed_format = "json"
        else:
            feed_format = "csv"

    if feed_format == "stix":
        raw = parse_stix_bundle(content)
    elif feed_format == "json":
        raw = parse_json_feed(content)
    else:
        raw = parse_csv_feed(content)

    iocs = []
    for item in raw:
        try:
            iocs.append(IOCCreate(
                value=item["value"],
                ioc_type=_normalize_ioc_type(item.get("type", "ip")),
                severity=_normalize_severity(item.get("severity", "medium")),
                source=item.get("source", feed_url),
                tags=item.get("tags", []),
            ))
        except Exception:
            continue

    return iocs


async def fetch_all_feeds() -> list[IOCCreate]:
    feeds = load_feeds()
    all_iocs: list[IOCCreate] = []

    for feed in feeds:
        url = feed.get("url", "")
        fmt = feed.get("format", "auto")
        name = feed.get("name", url)

        logger.info("Fetching feed: %s", name)
        raw_text = await fetch_feed(url)
        if raw_text is None:
            continue

        if fmt == "auto":
            if '"type"' in raw_text and '"objects"' in raw_text:
                fmt = "stix"
            elif raw_text.strip().startswith("[") or raw_text.strip().startswith("{"):
                fmt = "json"
            else:
                fmt = "csv"

        if fmt == "stix":
            raw = parse_stix_bundle(raw_text)
        elif fmt == "json":
            raw = parse_json_feed(raw_text)
        else:
            raw = parse_csv_feed(raw_text)

        for item in raw:
            try:
                all_iocs.append(IOCCreate(
                    value=item["value"],
                    ioc_type=_normalize_ioc_type(item.get("type", "ip")),
                    severity=_normalize_severity(item.get("severity", "medium")),
                    source=name,
                    tags=item.get("tags", []),
                ))
            except Exception:
                continue

        logger.info("Parsed %d IOCs from feed: %s", len(raw), name)

    return all_iocs
