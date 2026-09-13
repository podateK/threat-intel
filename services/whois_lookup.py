from __future__ import annotations

import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)


async def whois_lookup(value: str) -> dict:
    loop = asyncio.get_event_loop()
    try:
        import whois
        result = await loop.run_in_executor(None, whois.whois, value)
        if result is None:
            return {"found": False, "raw": None}
        return {
            "found": True,
            "domain_name": result.domain_name if hasattr(result, "domain_name") else None,
            "registrar": result.registrar if hasattr(result, "registrar") else None,
            "creation_date": str(result.creation_date) if hasattr(result, "creation_date") and result.creation_date else None,
            "expiration_date": str(result.expiration_date) if hasattr(result, "expiration_date") and result.expiration_date else None,
            "updated_date": str(result.updated_date) if hasattr(result, "updated_date") and result.updated_date else None,
            "name_servers": result.name_servers if hasattr(result, "name_servers") else [],
            "status": result.status if hasattr(result, "status") else [],
            "emails": result.emails if hasattr(result, "emails") else [],
            "org": result.org if hasattr(result, "org") else None,
            "country": result.country if hasattr(result, "country") else None,
            "registrant": result.registrant if hasattr(result, "registrant") else None,
            "dnssec": result.dnssec if hasattr(result, "dnssec") else None,
            "raw": str(result) if hasattr(result, "__str__") else None,
        }
    except Exception as e:
        logger.warning("WHOIS lookup failed for %s: %s", value, e)
        return {"found": False, "error": str(e)}
