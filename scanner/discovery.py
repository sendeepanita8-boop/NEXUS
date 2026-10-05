from scapy.all import ARP, Ether, srp

from database.database import get_connection, initialize_database

import socket
import ipaddress
import subprocess
import re

from datetime import datetime


# ============================================================
# CONFIGURATION
# ============================================================

# Common TCP ports used for basic asset/service identification.
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP"
}

# A device must be missed this many scans before
# it is marked OFFLINE.
OFFLINE_THRESHOLD = 2


# ============================================================
# TIME
# ============================================================

def now():
    return datetime.now().isoformat(
        timespec="seconds"
    )


# ============================================================
# NETWORK DISCOVERY
# ============================================================

def get_networks():

    """
    Detect all locally configured private IPv4 networks
    from Windows ipconfig output.

    Returns a list like:

    [
        {
            "interface": "Wireless LAN adapter Wi-Fi",
            "local_ip": "192.168.1.20",
            "subnet_mask": "255.255.255.0",
            "gateway": "192.168.1.1",
            "network": "192.168.1.0/24"
        }
    ]
    """

    try:

        output = subprocess.check_output(
            ["ipconfig"],
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

    except Exception as error:

        raise RuntimeError(
            f"Unable to read Windows network configuration: {error}"
        )


    # Keep each adapter header together with its detail lines. Blank-line
    # splitting separates the header from the IPv4 address on Windows.
    blocks = re.split(
        r"(?m)(?=^[^\r\n]*adapter[^:\r\n]*:\s*$)",
        output,
        flags=re.IGNORECASE
    )


    networks = []


    for block in blocks:

        lines = [
            line.strip()
            for line in block.splitlines()
            if line.strip()
        ]


        if not lines:
            continue


        # ----------------------------------------------------
        # INTERFACE NAME
        # ----------------------------------------------------

        interface_match = re.search(
            r"^\s*([^:\r\n]*adapter[^:\r\n]*):\s*$",
            block,
            re.IGNORECASE | re.MULTILINE
        )
        interface = (
            interface_match.group(1).strip()
            if interface_match
            else lines[0].rstrip(":")
        )


        # ----------------------------------------------------
        # IPV4
        # ----------------------------------------------------

        ipv4_matches = re.findall(
            r"IPv4 Address[^\:]*:\s*"
            r"(\d+\.\d+\.\d+\.\d+)",
            block,
            re.IGNORECASE
        )


        if not ipv4_matches:
            continue


        local_ip = ipv4_matches[0]


        # ----------------------------------------------------
        # VALIDATE IP
        # ----------------------------------------------------

        try:

            address = ipaddress.ip_address(
                local_ip
            )

        except ValueError:

            continue


        # Ignore loopback.
        if address.is_loopback:
            continue


        # Ignore Windows APIPA.
        if local_ip.startswith("169.254."):
            continue


        # Only private networks are automatically considered.
        if not address.is_private:
            continue


        # ----------------------------------------------------
        # SUBNET MASK
        # ----------------------------------------------------

        mask_matches = re.findall(
            r"Subnet Mask[^\:]*:\s*"
            r"(\d+\.\d+\.\d+\.\d+)",
            block,
            re.IGNORECASE
        )


        if mask_matches:

            subnet_mask = mask_matches[0]

        else:

            # Fallback.
            subnet_mask = "255.255.255.0"


        # ----------------------------------------------------
        # GATEWAY
        # ----------------------------------------------------

        gateway_matches = re.findall(
            r"Default Gateway[^\:]*:\s*"
            r"(\d+\.\d+\.\d+\.\d+)",
            block,
            re.IGNORECASE
        )


        gateway = "Unknown"


        for item in gateway_matches:

            if item:

                gateway = item

                break


        # ----------------------------------------------------
        # NETWORK CIDR
        # ----------------------------------------------------

        try:

            network = ipaddress.ip_network(
                f"{local_ip}/{subnet_mask}",
                strict=False
            )

        except ValueError:

            continue


        # ----------------------------------------------------
        # SAVE
        # ----------------------------------------------------

        networks.append(
            {
                "interface": interface,
                "local_ip": local_ip,
                "subnet_mask": subnet_mask,
                "gateway": gateway,
                "network": str(network)
            }
        )


    # --------------------------------------------------------
    # REMOVE DUPLICATES
    # --------------------------------------------------------

    unique = {}

    for item in networks:

        key = (
            item["network"],
            item["local_ip"]
        )

        unique[key] = item


    return list(
        unique.values()
    )


# ============================================================
# COMPATIBILITY NETWORK FUNCTION
# ============================================================

def get_network_info():

    """
    Returns the first detected network.

    Kept for compatibility with older parts of NEXUS.
    """

    networks = get_networks()


    if not networks:

        raise RuntimeError(
            "No private IPv4 network detected."
        )


    first = networks[0]


    return {
        "local_ip":
            first["local_ip"],

        "subnet_mask":
            first["subnet_mask"],

        "gateway":
            first["gateway"],

        "network":
            first["network"],

        "networks":
            networks
    }


# ============================================================
# PORT SCANNING
# ============================================================

def check_ports(ip):

    """
    Check common TCP ports on a discovered device.

    Returns:

    80:HTTP, 443:HTTPS, 445:SMB
    """

    open_ports = []


    for port, service in COMMON_PORTS.items():

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(0.30)


        try:

            result = sock.connect_ex(
                (ip, port)
            )


            if result == 0:

                open_ports.append(
                    f"{port}:{service}"
                )


        except (
            socket.timeout,
            socket.error,
            OSError
        ):

            pass


        finally:

            sock.close()


    if not open_ports:

        return "None"


    return ", ".join(
        open_ports
    )


# ============================================================
# HOSTNAME
# ============================================================

def get_hostname(ip):

    try:

        hostname = socket.gethostbyaddr(
            ip
        )[0]

        return hostname


    except (
        socket.herror,
        socket.gaierror,
        OSError
    ):

        return "Unknown"


# ============================================================
# PORT PARSER
# ============================================================

def get_port_numbers(value):

    result = set()


    if not value:
        return result


    if value == "None":
        return result


    for item in value.split(","):

        item = item.strip()


        if not item:
            continue


        parts = item.split(":")


        if parts:

            result.add(
                parts[0]
            )


    return result


# ============================================================
# ALERT CREATION
# ============================================================

def add_alert(
    cursor,
    alert_type,
    message,
    ip
):

    cursor.execute(
        """
        INSERT INTO alerts
        (
            alert_type,
            message,
            ip_address,
            created_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            alert_type,
            message,
            ip,
            now()
        )
    )


def add_activity(
    cursor,
    mac,
    event_type,
    message,
    ip
):

    device = cursor.execute(
        "SELECT id FROM devices WHERE mac_address = ?",
        (mac,)
    ).fetchone()

    cursor.execute(
        """
        INSERT INTO device_activity
        (device_id, mac_address, event_type, message, ip_address, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            device[0] if device else None,
            mac,
            event_type,
            message,
            ip,
            now()
        )
    )


# ============================================================
# DISCOVER ONE NETWORK
# ============================================================

def discover_network(
    network_info,
    cursor,
    previous_devices,
    discovered_macs
):

    network = network_info["network"]

    interface = network_info["interface"]


    print()
    print("-" * 70)

    print(
        f"Scanning network : {network}"
    )

    print(
        f"Local IP         : "
        f"{network_info['local_ip']}"
    )

    print(
        f"Gateway          : "
        f"{network_info['gateway']}"
    )

    print(
        f"Interface        : "
        f"{interface}"
    )

    print("-" * 70)


    # --------------------------------------------------------
    # ARP DISCOVERY
    # --------------------------------------------------------

    packet = (
        Ether(
            dst="ff:ff:ff:ff:ff:ff"
        )
        /
        ARP(
            pdst=network
        )
    )


    try:

        answered = srp(
            packet,
            timeout=3,
            retry=1,
            verbose=False
        )[0]


    except Exception as error:

        print(
            f"Unable to scan {network}: "
            f"{error}"
        )

        return 0


    print(
        f"Devices responding: "
        f"{len(answered)}"
    )


    # --------------------------------------------------------
    # PROCESS DEVICES
    # --------------------------------------------------------

    for sent, received in answered:

        ip = received.psrc

        mac = received.hwsrc.lower()


        discovered_macs.add(
            mac
        )


        current_time = now()


        # ----------------------------------------------------
        # HOSTNAME
        # ----------------------------------------------------

        hostname = get_hostname(
            ip
        )


        print()
        print(
            f"Checking device: {ip}"
        )

        print(
            f"MAC: {mac}"
        )

        print(
            f"Hostname: {hostname}"
        )


        # ----------------------------------------------------
        # PORT SCAN
        # ----------------------------------------------------

        open_ports = check_ports(
            ip
        )


        print(
            f"Open ports: {open_ports}"
        )


        # ----------------------------------------------------
        # PREVIOUS DEVICE?
        # ----------------------------------------------------

        previous = previous_devices.get(
            mac
        )


        # ====================================================
        # EXISTING DEVICE
        # ====================================================

        if previous:

            old_status = (
                previous["status"]
            )


            old_ports = (
                previous["open_ports"]
                or "None"
            )


            # ------------------------------------------------
            # DEVICE BACK ONLINE
            # ------------------------------------------------

            if old_status == "OFFLINE":

                add_alert(
                    cursor,
                    "DEVICE_BACK_ONLINE",
                    (
                        "Device came back online: "
                        f"{ip}"
                    ),
                    ip
                )

                add_activity(
                    cursor,
                    mac,
                    "DEVICE_BACK_ONLINE",
                    f"Device came back online at {ip}",
                    ip
                )

            add_activity(
                cursor,
                mac,
                "DEVICE_SEEN",
                f"Device responded to discovery; services observed: {open_ports}",
                ip
            )


            # ------------------------------------------------
            # PORT CHANGES
            # ------------------------------------------------

            old_port_numbers = (
                get_port_numbers(
                    old_ports
                )
            )


            new_port_numbers = (
                get_port_numbers(
                    open_ports
                )
            )


            # ------------------------------------------------
            # NEW PORT
            # ------------------------------------------------

            for port in (
                new_port_numbers -
                old_port_numbers
            ):

                try:

                    service = COMMON_PORTS.get(
                        int(port),
                        "Unknown"
                    )

                except ValueError:

                    service = "Unknown"


                add_alert(
                    cursor,
                    "NEW_PORT",
                    (
                        f"New open port: "
                        f"{ip}:{port} "
                        f"({service})"
                    ),
                    ip
                )

                add_activity(
                    cursor,
                    mac,
                    "PORT_OPENED",
                    f"Observed {service} on TCP port {port}",
                    ip
                )


            # ------------------------------------------------
            # CLOSED PORT
            # ------------------------------------------------

            for port in (
                old_port_numbers -
                new_port_numbers
            ):

                try:

                    service = COMMON_PORTS.get(
                        int(port),
                        "Unknown"
                    )

                except ValueError:

                    service = "Unknown"


                add_alert(
                    cursor,
                    "PORT_CLOSED",
                    (
                        f"Port closed: "
                        f"{ip}:{port} "
                        f"({service})"
                    ),
                    ip
                )

                add_activity(
                    cursor,
                    mac,
                    "PORT_CLOSED",
                    f"No response from {service} on TCP port {port}",
                    ip
                )


            # ------------------------------------------------
            # UPDATE DEVICE
            # ------------------------------------------------

            cursor.execute(
                """
                UPDATE devices
                SET
                    ip_address = ?,
                    hostname = ?,
                    network = ?,
                    interface = ?,
                    last_seen = ?,
                    status = 'ONLINE',
                    open_ports = ?,
                    missed_scans = 0
                WHERE mac_address = ?
                """,
                (
                    ip,
                    hostname,
                    network,
                    interface,
                    current_time,
                    open_ports,
                    mac
                )
            )

            print(
                f"[ONLINE] "
                f"{ip} | {hostname}"
            )


        # ====================================================
        # NEW DEVICE
        # ====================================================

        else:

            add_alert(
                cursor,
                "NEW_DEVICE",
                (
                    "New device detected: "
                    f"{ip}"
                ),
                ip
            )


            cursor.execute(
                """
                INSERT INTO devices
                (
                    ip_address,
                    mac_address,
                    hostname,
                    network,
                    interface,
                    first_seen,
                    last_seen,
                    status,
                    open_ports,
                    missed_scans
                )
                VALUES
                (
                    ?, ?, ?, ?, ?, ?,
                    ?, 'ONLINE', ?, 0
                )
                """,
                (
                    ip,
                    mac,
                    hostname,
                    network,
                    interface,
                    current_time,
                    current_time,
                    open_ports
                )
            )

            add_activity(
                cursor,
                mac,
                "DEVICE_DISCOVERED",
                f"New device discovered with services: {open_ports}",
                ip
            )


            print(
                f"[NEW DEVICE] "
                f"{ip} | {hostname}"
            )


    return len(answered)


# ============================================================
# MAIN DISCOVERY ENGINE
# ============================================================

def discover_devices():

    initialize_database()

    print()
    print("=" * 75)

    print(
        "NEXUS - NETWORK ASSET INTELLIGENCE"
    )

    print(
        "MULTI-NETWORK DISCOVERY ENGINE"
    )

    print("=" * 75)


    # --------------------------------------------------------
    # DETECT ALL NETWORKS
    # --------------------------------------------------------

    networks = get_networks()


    if not networks:

        raise RuntimeError(
            "No private IPv4 networks detected."
        )


    print()
    print(
        f"Networks detected: "
        f"{len(networks)}"
    )


    # --------------------------------------------------------
    # DISPLAY NETWORKS
    # --------------------------------------------------------

    for index, network in enumerate(
        networks,
        start=1
    ):

        print(
            f"[{index}] "
            f"{network['network']} "
            f"| IP: {network['local_ip']} "
            f"| Gateway: {network['gateway']} "
            f"| Interface: {network['interface']}"
        )


    # --------------------------------------------------------
    # DATABASE
    # --------------------------------------------------------

    connection = get_connection()

    cursor = connection.cursor()


    # --------------------------------------------------------
    # PREVIOUS DEVICES
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT
            mac_address,
            ip_address,
            hostname,
            status,
            open_ports,
            missed_scans
        FROM devices
        """
    )


    previous_devices = {}


    for row in cursor.fetchall():

        previous_devices[row[0]] = {

            "ip":
                row[1],

            "hostname":
                row[2],

            "status":
                row[3],

            "open_ports":
                row[4] or "None",

            "missed_scans":
                row[5] or 0

        }


    # --------------------------------------------------------
    # DEVICES FOUND DURING CURRENT SCAN
    # --------------------------------------------------------

    discovered_macs = set()


    total_found = 0


    # --------------------------------------------------------
    # SCAN EVERY NETWORK
    # --------------------------------------------------------

    for network_info in networks:

        total_found += (
            discover_network(
                network_info,
                cursor,
                previous_devices,
                discovered_macs
            )
        )


    # --------------------------------------------------------
    # CHECK DEVICES NOT FOUND
    # --------------------------------------------------------

    for mac, device in previous_devices.items():

        if mac in discovered_macs:

            continue


        old_status = (
            device["status"]
        )


        missed = (
            device["missed_scans"]
            or 0
        )


        missed += 1


        # ====================================================
        # MISSED BUT NOT YET OFFLINE
        # ====================================================

        if (
            old_status == "ONLINE"
            and
            missed < OFFLINE_THRESHOLD
        ):

            cursor.execute(
                """
                UPDATE devices
                SET
                    missed_scans = ?
                WHERE mac_address = ?
                """,
                (
                    missed,
                    mac
                )
            )


            print(
                f"[MISSED] "
                f"{device['ip']} "
                f"({missed}/"
                f"{OFFLINE_THRESHOLD})"
            )


        # ====================================================
        # DEVICE BECOMES OFFLINE
        # ====================================================

        elif (
            old_status == "ONLINE"
            and
            missed >= OFFLINE_THRESHOLD
        ):

            cursor.execute(
                """
                UPDATE devices
                SET
                    status = 'OFFLINE',
                    missed_scans = ?
                WHERE mac_address = ?
                """,
                (
                    missed,
                    mac
                )
            )


            add_alert(
                cursor,
                "DEVICE_OFFLINE",
                (
                    "Device went offline: "
                    f"{device['ip']}"
                ),
                device["ip"]
            )

            add_activity(
                cursor,
                mac,
                "DEVICE_OFFLINE",
                f"Device missed {missed} discovery scans",
                device["ip"]
            )


            print(
                f"[OFFLINE] "
                f"{device['ip']} | "
                f"{device['hostname']}"
            )


        # ====================================================
        # ALREADY OFFLINE
        # ====================================================

        elif old_status == "OFFLINE":

            cursor.execute(
                """
                UPDATE devices
                SET
                    missed_scans = ?
                WHERE mac_address = ?
                """,
                (
                    missed,
                    mac
                )
            )


            print(
                f"[STILL OFFLINE] "
                f"{device['ip']} | "
                f"Missed scans: {missed}"
            )


    # --------------------------------------------------------
    # UPDATE SCAN INFORMATION
    # --------------------------------------------------------

    current_time = now()

    network_names = ", ".join(
        network["network"]
        for network in networks
    )


    cursor.execute(
        """
        INSERT INTO scan_meta
        (
            id,
            last_scan,
            networks
        )
        VALUES
        (
            1,
            ?,
            ?
        )
        ON CONFLICT (id) DO UPDATE SET
            last_scan = EXCLUDED.last_scan,
            networks = EXCLUDED.networks
        """,
        (
            current_time,
            network_names
        )
    )


    # --------------------------------------------------------
    # SAVE DATABASE
    # --------------------------------------------------------

    connection.commit()


    # --------------------------------------------------------
    # CLOSE DATABASE
    # --------------------------------------------------------

    connection.close()


    # --------------------------------------------------------
    # FINAL SUMMARY
    # --------------------------------------------------------

    print()
    print("=" * 75)

    print(
        "DISCOVERY COMPLETED"
    )

    print(
        f"Networks scanned : "
        f"{len(networks)}"
    )

    print(
        f"Devices found    : "
        f"{total_found}"
    )

    print(
        f"Completed at     : "
        f"{current_time}"
    )

    print("=" * 75)


    return {
        "success": True,
        "networks_scanned": len(networks),
        "devices_found": total_found,
        "completed_at": current_time
    }


# ============================================================
# RUN DISCOVERY
# ============================================================

if __name__ == "__main__":

    try:

        result = discover_devices()

        print()
        print(
            "Discovery result:"
        )

        print(
            result
        )


    except KeyboardInterrupt:

        print()
        print(
            "Discovery stopped by user."
        )


    except Exception as error:

        print()
        print(
            "Discovery failed:"
        )

        print(
            error
        )