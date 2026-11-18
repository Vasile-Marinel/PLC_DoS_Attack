"""
legit_client.py
----------------
PAS 2 din cerinta proiectului: client normal care trimite cereri legitime,
la interval regulat, catre server-ul PLC - ca o statie SCADA / HMI reala
care interogheaza periodic registrele PLC-ului.

Ruleaza pentru DURATION_SEC secunde, trimitand cate o cerere READ pe secunda,
si masoara latenta fiecarei cereri + daca a reusit sau nu. Rezultatele sunt
scrise intr-un CSV, folosit apoi de compare_results.py pentru a observa
degradarea de performanta (pasul 4) si pentru a compara baseline vs protejat
(pasul 6).

Rulare:
    python legit_client.py <nume_fisier_rezultat.csv> [durata_secunde]

Exemplu:
    python legit_client.py results/legit_baseline.csv 60
"""

import socket
import time
import csv
import sys
import random

from common import HOST, PORT, SOCKET_TIMEOUT_SEC, LEGIT_CLIENT_SOURCE_IP

DURATION_SEC_DEFAULT = 60
REQUEST_INTERVAL_SEC = 1.0  # o cerere legitima pe secunda


def send_one_request():
    reg = random.randint(0, 19)
    t0 = time.time()
    try:
        # Ne legam explicit pe a doua adresa de loopback, ca sa aparem fata
        # de server ca o gazda distincta de atacator (vezi common.py).
        with socket.create_connection(
            (HOST, PORT), timeout=SOCKET_TIMEOUT_SEC,
            source_address=(LEGIT_CLIENT_SOURCE_IP, 0),
        ) as s:
            s.sendall(f"READ {reg}\n".encode())
            s.settimeout(SOCKET_TIMEOUT_SEC)
            data = s.recv(1024)
            t1 = time.time()
            ok = data.startswith(b"OK")
            status = data.decode(errors="ignore").strip() if data else "EMPTY"
            return True, ok, (t1 - t0) * 1000.0, status
    except Exception as e:
        t1 = time.time()
        return False, False, (t1 - t0) * 1000.0, f"EXC:{type(e).__name__}"


def main():
    if len(sys.argv) < 2:
        print("Utilizare: python legit_client.py <fisier_rezultat.csv> [durata_secunde]")
        sys.exit(1)

    out_path = sys.argv[1]
    duration = float(sys.argv[2]) if len(sys.argv) > 2 else DURATION_SEC_DEFAULT

    print(f"[legit_client] Trimit cate o cerere/secunda timp de {duration:.0f}s catre {HOST}:{PORT}")
    print(f"[legit_client] Rezultate in: {out_path}")

    results = []
    start = time.time()
    next_tick = start

    while (time.time() - start) < duration:
        elapsed = time.time() - start
        connected, ok, latency_ms, status = send_one_request()
        results.append((f"{elapsed:.2f}", connected, ok, f"{latency_ms:.1f}", status))

        if not connected or not ok:
            print(f"  [t={elapsed:5.1f}s] ESUAT  latenta={latency_ms:7.1f}ms  status={status}")
        elif latency_ms > 200:
            print(f"  [t={elapsed:5.1f}s] LENT   latenta={latency_ms:7.1f}ms  status={status}")

        next_tick += REQUEST_INTERVAL_SEC
        sleep_time = next_tick - time.time()
        if sleep_time > 0:
            time.sleep(sleep_time)

    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["t_sec", "connected", "ok", "latency_ms", "status"])
        writer.writerows(results)

    total = len(results)
    succeeded = sum(1 for r in results if r[1] and r[2])
    print(f"[legit_client] Gata. {succeeded}/{total} cereri reusite "
          f"({100.0 * succeeded / max(total, 1):.1f}%).")


if __name__ == "__main__":
    main()
