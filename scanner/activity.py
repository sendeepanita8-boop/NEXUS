import re
import threading
from datetime import datetime

from scapy.all import DNS, DNSQR, IP, sniff

from database.database import get_connection


_monitor_started = False
_monitor_lock = threading.Lock()


CATEGORY_RULES = {
    "VIDEO": ("youtube.", "netflix.", "twitch.", "vimeo.", "tiktok."),
    "SOCIAL": ("instagram.", "facebook.", "snapchat.", "twitter.", "x.com", "reddit."),
    "MESSAGING": ("whatsapp.", "telegram.", "discord.", "signal."),
    "GAMING": ("steam.", "epicgames.", "xbox.", "playstation.", "roblox."),
    "PRODUCTIVITY": ("microsoft.", "office.", "google.", "github.", "slack.", "zoom."),
    "SHOPPING": ("amazon.", "ebay.", "walmart.", "etsy."),
}


def classify_domain(domain):
    lowered = domain.lower()
    for category, patterns in CATEGORY_RULES.items():
        if any(pattern in lowered for pattern in patterns):
            return category
    return "OTHER"


def record_dns_query(packet):
    if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
        return

    query = packet[DNSQR].qname
    if isinstance(query, bytes):
        query = query.decode("utf-8", errors="ignore")
    domain = re.sub(r"\.$", "", str(query)).strip().lower()
    if not domain or not packet.haslayer(IP):
        return

    connection = get_connection()
    connection.execute(
        """
        INSERT INTO network_activity (ip_address, domain, category, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            packet[IP].src,
            domain,
            classify_domain(domain),
            datetime.now().isoformat(timespec="seconds")
        )
    )
    connection.commit()
    connection.close()


def monitor_dns():
    try:
        sniff(
            filter="udp port 53 or tcp port 53",
            prn=record_dns_query,
            store=False
        )
    except Exception as error:
        print(f"DNS activity monitor unavailable: {error}")


def start_dns_monitor():
    global _monitor_started
    with _monitor_lock:
        if _monitor_started:
            return
        _monitor_started = True
        threading.Thread(target=monitor_dns, daemon=True, name="dns-activity-monitor").start()