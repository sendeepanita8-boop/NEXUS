import os
import ssl
from urllib.parse import parse_qs, unquote, urlparse

import pg8000.dbapi


DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL")
DB_NAME = "PostgreSQL"


class _CursorAdapter:
    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, query, parameters=()):
        self._cursor.execute(query.replace("?", "%s"), parameters)
        return self

    def __iter__(self):
        return iter(self._cursor)

    def __getattr__(self, name):
        return getattr(self._cursor, name)


class _ConnectionAdapter:
    def __init__(self, connection):
        self._connection = connection

    def cursor(self):
        return _CursorAdapter(self._connection.cursor())

    def execute(self, query, parameters=()):
        return self.cursor().execute(query, parameters)

    def __getattr__(self, name):
        return getattr(self._connection, name)


def get_database_url():
    return os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL") or DATABASE_URL


def get_connection():
    db_url = get_database_url()
    if not db_url:
        raise RuntimeError(
            "Set DATABASE_URL to a PostgreSQL connection string, or configure "
            "POSTGRES_URL from a Vercel Postgres integration."
        )
    url = urlparse(db_url)
    query = parse_qs(url.query)
    ssl_context = None
    if query.get("sslmode", ["require"])[0] != "disable":
        ssl_context = ssl.create_default_context()
    connection = pg8000.dbapi.connect(
        user=unquote(url.username or ""),
        password=unquote(url.password or ""),
        host=url.hostname,
        port=url.port or 5432,
        database=url.path.lstrip("/"),
        ssl_context=ssl_context,
        application_name="nexus-network-asset-monitor",
    )
    return _ConnectionAdapter(connection)


def initialize_database():
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS devices (
            id BIGSERIAL PRIMARY KEY,
            ip_address TEXT NOT NULL,
            mac_address TEXT NOT NULL UNIQUE,
            hostname TEXT DEFAULT 'Unknown',
            network TEXT DEFAULT 'Unknown',
            interface TEXT DEFAULT 'Unknown',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ONLINE',
            open_ports TEXT DEFAULT 'None',
            missed_scans INTEGER DEFAULT 0
        )
        """
    )
    columns = {
        "ip_address": "TEXT",
        "mac_address": "TEXT",
        "hostname": "TEXT DEFAULT 'Unknown'",
        "network": "TEXT DEFAULT 'Unknown'",
        "interface": "TEXT DEFAULT 'Unknown'",
        "first_seen": "TEXT",
        "last_seen": "TEXT",
        "status": "TEXT NOT NULL DEFAULT 'ONLINE'",
        "open_ports": "TEXT DEFAULT 'None'",
        "missed_scans": "INTEGER DEFAULT 0",
    }
    existing = {
        row[0]
        for row in cursor.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = current_schema() AND table_name = ?
            """,
            ("devices",),
        )
    }
    for name, definition in columns.items():
        if name not in existing:
            cursor.execute(f"ALTER TABLE devices ADD COLUMN {name} {definition}")
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id BIGSERIAL PRIMARY KEY,
            alert_type TEXT NOT NULL,
            message TEXT NOT NULL,
            ip_address TEXT,
            created_at TEXT NOT NULL,
            acknowledged INTEGER DEFAULT 0
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            last_scan TEXT,
            networks TEXT
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS device_activity (
            id BIGSERIAL PRIMARY KEY,
            device_id BIGINT,
            mac_address TEXT,
            event_type TEXT NOT NULL,
            message TEXT NOT NULL,
            ip_address TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS network_activity (
            id BIGSERIAL PRIMARY KEY,
            ip_address TEXT NOT NULL,
            domain TEXT NOT NULL,
            category TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        INSERT INTO scan_meta (id, last_scan, networks)
        VALUES (1, NULL, '')
        ON CONFLICT (id) DO NOTHING
        """
    )
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_device_activity_device ON device_activity(device_id, created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_network_activity_time ON network_activity(created_at)")
    connection.commit()
    connection.close()


if __name__ == "__main__":
    initialize_database()
    print(f"NEXUS database ready: {DB_NAME}")
