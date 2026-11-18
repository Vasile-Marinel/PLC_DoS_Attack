"""
plc_server.py
-------------
PAS 1 din cerinta proiectului: server simplu care imita un PLC.

Varianta VULNERABILA (baseline, fara nicio protectie):
  - accepta conexiuni TCP intr-o bucla simpla, BLOCANTA, pe un singur fir
    de executie (single-threaded, exact cum sunt multe stive de retea de pe
    echipamente industriale ieftine / cu resurse limitate).
  - trateaza o conexiune complet (citeste, "proceseaza" cu o mica intarziere,
    raspunde, inchide) inainte sa accepte urmatoarea.
  - NU are: limita de rata (rate limiting), coada marginita, limita de
    conexiuni concurente, timeout agresiv.

Aceasta varianta este folosita ca sa demonstram pasii 3-4 din cerinta:
flood-ul de pachete + degradarea / caderea sistemului.

Rulare:
    python plc_server.py

Oprire: Ctrl+C
"""

import socket
import threading
import time
import csv
import os

from common import HOST, PORT, PROCESSING_DELAY_SEC, make_registers, handle_command, now_ms

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
STATS_LOG = os.path.join(LOG_DIR, "server_baseline_stats.csv")

registers = make_registers()

# Contoare globale, folosite doar pentru statistici / raportare periodica
stats_lock = threading.Lock()
total_handled = 0
total_connections_seen = 0
start_time = None


def stats_logger():
    """Scrie la fiecare 0.5s o linie cu starea serverului, ca sa putem
    trasa ulterior graficul de degradare a performantei in timp."""
    with open(STATS_LOG, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["t_sec", "total_handled", "total_connections_seen", "throughput_req_per_sec"])
        last_handled = 0
        while True:
            time.sleep(0.5)
            with stats_lock:
                handled = total_handled
                seen = total_connections_seen
            elapsed = time.time() - start_time
            throughput = (handled - last_handled) / 0.5
            last_handled = handled
            writer.writerow([f"{elapsed:.2f}", handled, seen, f"{throughput:.1f}"])
            f.flush()


def handle_client(conn: socket.socket, addr):
    global total_handled
    try:
        conn.settimeout(10)
        data = conn.recv(1024)
        if not data:
            return
        line = data.decode(errors="ignore")

        # Simuleaza timpul de procesare / scanare al unui PLC real.
        time.sleep(PROCESSING_DELAY_SEC)

        response = handle_command(line, registers)
        conn.sendall((response + "\n").encode())
    except Exception:
        pass
    finally:
        conn.close()
        with stats_lock:
            total_handled += 1


def main():
    global start_time, total_connections_seen

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(128)  # backlog implicit, generos, fara alta protectie

    start_time = time.time()
    threading.Thread(target=stats_logger, daemon=True).start()

    print(f"[plc_server VULNERABIL] Ascult pe {HOST}:{PORT} (single-threaded, fara protectii)")
    print(f"[plc_server VULNERABIL] Statistici scrise in: {STATS_LOG}")

    try:
        while True:
            conn, addr = server_sock.accept()
            with stats_lock:
                total_connections_seen += 1
            # NOTA: tratarea se face SINCRON, pe acelasi fir care accepta
            # conexiuni noi. Asta inseamna ca, daca un atacator deschide multe
            # conexiuni simultan, ele se pun la coada la nivel de SO
            # (backlog), iar latenta perceputa de clientii legitimi creste
            # liniar cu numarul de cereri in asteptare. Exact comportamentul
            # pe care vrem sa-l demonstram.
            handle_client(conn, addr)
    except KeyboardInterrupt:
        print("\n[plc_server VULNERABIL] Oprire server.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()
