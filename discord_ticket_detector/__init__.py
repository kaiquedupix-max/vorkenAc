"""Classificação de eventos de tickets fornecidos com consentimento explícito.

Não acessa Discord, credenciais, sessões, caches privados ou mensagens.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import re
import unicodedata
from typing import Iterable, Mapping

EVENT_PATTERNS = {
    "opened": (r"\\bticket\\s*(?:created|opened|open)\\b", r"\\b(?:ticket|chamado)\\s*(?:aberto|criado)\\b", r"\\b(?:nuevo ticket|ticket abierto)\\b"),
    "closed": (r"\\bticket\\s*(?:closed|deleted|archived)\\b", r"\\b(?:ticket|chamado)\\s*(?:fechado|encerrado|arquivado)\\b", r"\\b(?:ticket cerrado|ticket archivado)\\b"),
}
ORDER_PATTERN = re.compile(r"\\b(?:purchase completed|order (?:ready|completed)|compra (?:aprovada|concluida)|pedido (?:entregue|concluido))\\b")
SNOWFLAKE = re.compile(r"^\\d{17,20}$")


def normalize(value: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", value.casefold()) if not unicodedata.combining(c))


@dataclass(frozen=True)
class TicketFinding:
    event: str
    server_name: str | None
    server_id: str | None
    bot_name: str | None
    occurred_at: str | None
    source: str
    confidence: str
    classification: str
    review_reason: str

    def to_dict(self) -> dict:
        return asdict(self)


def classify(record: Mapping[str, object], known_cheat_servers: Iterable[str] = ()) -> TicketFinding | None:
    """Recebe metadados/notificação fornecidos voluntariamente, nunca texto de DMs."""
    if record.get("consent") is not True:
        return None
    if record.get("source") not in {"user_submitted_notification", "authorized_windows_notification"}:
        return None
    message = str(record.get("notification_text") or "")[:2000]
    normalized = normalize(message)
    event = next((kind for kind, patterns in EVENT_PATTERNS.items()
                  if any(re.search(pattern, normalized) for pattern in patterns)), None)
    if event is None and ORDER_PATTERN.search(normalized):
        event = "order_related"
    if event is None:
        return None

    server_name = str(record.get("server_name") or "").strip()[:120] or None
    raw_id = str(record.get("server_id") or "").strip()
    server_id = raw_id if SNOWFLAKE.fullmatch(raw_id) else None
    bot_name = str(record.get("bot_name") or "").strip()[:120] or None
    timestamp = str(record.get("occurred_at") or "").strip()
    try:
        if timestamp:
            datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        timestamp = ""
    known = {normalize(str(name).strip()) for name in known_cheat_servers}
    catalog_match = bool((server_name and normalize(server_name) in known) or (server_id and server_id in known))
    confidence = "medium" if server_id else "low"
    if catalog_match:
        classification = "manual_review"
        reason = "Servidor consta no catálogo; ticket isolado não comprova compra ou uso de cheat."
    elif server_name or server_id:
        classification = "inventory"
        reason = "Origem identificada, mas não confirmada como loja de cheats."
    else:
        classification = "inconclusive"
        reason = "Notificação não permite identificar o servidor de origem."
    return TicketFinding(event, server_name, server_id, bot_name, timestamp or None,
                         str(record["source"]), confidence, classification, reason)
