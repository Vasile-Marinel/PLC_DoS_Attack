"""
run_experiment.py
------------------
PAS 4 din Cerinta:
Orchestreaza un experiment complet: porneste server-ul (vulnerabil sau
protejat), clientul legitim (care ruleaza tot timpul experimentului) si
atacatorul (care porneste dupa o perioada de "liniste" si ataca o vreme,
apoi se opreste) - exact scenariul inainte/in timpul/dupa atac necesar
pentru a observa degradarea (pasul 4) si a compara rezultatele (pasul 6).

Rulare:
    py -3 run_experiment.py baseline    -pentru serverul PLC vulnerbail
    py -3 run_experiment.py protected   -pentru serverul PLC protejat

Rezultatele clientului legitim sunt scrise in:
    results/legit_baseline.csv
    results/legit_protected.csv

iar statisticile server-ului in:
    logs/server_baseline_stats.csv
    logs/server_protected_stats.csv

Dupa ce rulez ambele variante, folosesc 'py -3 compare_results.py' pentru raport
si grafic comparativ
"""

import subprocess
import sys
import time
import os
import signal

BASE_DIR = os.path.dirname(__file__)
RESULTS_DIR = os.path.join(BASE_DIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

# Parametrii experimentului - usor de ajustat
TOTAL_DURATION = 60      # durata totala a clientului legitim (secunde)
ATTACK_START_DELAY = 15  # atacul incepe dupa 15s de trafic normal
ATTACK_DURATION = 30     # atacul dureaza 30s (se opreste la t=45s)
ATTACK_THREADS = 50      # concurenta atacatorului


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("baseline", "protected"):
        print("Utilizare: python run_experiment.py [baseline|protected]")
        sys.exit(1)

    mode = sys.argv[1]
    server_script = "plc_server.py" if mode == "baseline" else "plc_server_protected.py"
    legit_out = os.path.join(RESULTS_DIR, f"legit_{mode}.csv")

    python = sys.executable

    print(f"=== Experiment: {mode} ===")
    print(f"Server: {server_script}")

    server_proc = subprocess.Popen(
        [python, os.path.join(BASE_DIR, server_script)],
        cwd=BASE_DIR,
    )
    time.sleep(1.5)  # timp sa porneasca server-ul

    legit_proc = subprocess.Popen(
        [python, os.path.join(BASE_DIR, "legit_client.py"), legit_out, str(TOTAL_DURATION)],
        cwd=BASE_DIR,
    )

    print(f"Clientul legitim ruleaza {TOTAL_DURATION}s. "
          f"Atacul incepe la t={ATTACK_START_DELAY}s si dureaza {ATTACK_DURATION}s.")

    time.sleep(ATTACK_START_DELAY)

    print(">>> PORNESC ATACUL <<<")
    attacker_proc = subprocess.Popen(
        [python, os.path.join(BASE_DIR, "attacker.py"), str(ATTACK_DURATION), str(ATTACK_THREADS)],
        cwd=BASE_DIR,
    )

    attacker_proc.wait()
    print(">>> ATAC OPRIT <<<")

    legit_proc.wait()
    print("Clientul legitim a terminat.")

    # Oprim server-ul
    if os.name == "nt":
        server_proc.terminate()
    else:
        server_proc.send_signal(signal.SIGINT)
    try:
        server_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server_proc.kill()

    print(f"=== Experiment '{mode}' terminat. Rezultate: {legit_out} ===")


if __name__ == "__main__":
    main()
