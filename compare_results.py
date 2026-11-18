"""
compare_results.py
-------------------
PAS 6 din cerinta proiectului: re-testare si comparare a rezultatelor
intre varianta vulnerabila (baseline) si cea protejata.

Citeste results/legit_baseline.csv si results/legit_protected.csv (produse
de run_experiment.py), calculeaza statistici pe 3 ferestre de timp
(inainte de atac / in timpul atacului / dupa atac) si genereaza:
  - un raport text in consola + results/raport_comparativ.txt
  - un grafic PNG cu latenta in timp pentru ambele variante,
    results/comparatie_latenta.png

Rulare (dupa ce ai rulat deja ambele experimente):
    python compare_results.py
"""

import csv
import os
import statistics

BASE_DIR = os.path.dirname(__file__)
RESULTS_DIR = os.path.join(BASE_DIR, "results")

ATTACK_START = 15
ATTACK_END = 45


def load(path):
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append({
                "t": float(r["t_sec"]),
                "connected": r["connected"] == "True",
                "ok": r["ok"] == "True",
                "latency_ms": float(r["latency_ms"]),
                "status": r["status"],
            })
    return rows


def window_stats(rows, lo, hi):
    sel = [r for r in rows if lo <= r["t"] < hi]
    if not sel:
        return None
    total = len(sel)
    success = [r for r in sel if r["connected"] and r["ok"]]
    success_rate = 100.0 * len(success) / total
    latencies = [r["latency_ms"] for r in success] if success else [r["latency_ms"] for r in sel]
    return {
        "n": total,
        "success_rate": success_rate,
        "avg_latency": statistics.mean(latencies) if latencies else float("nan"),
        "max_latency": max(latencies) if latencies else float("nan"),
        "p95_latency": (sorted(latencies)[int(0.95 * len(latencies)) - 1] if len(latencies) >= 2
                        else (latencies[0] if latencies else float("nan"))),
    }


def report_for(name, rows):
    lines = [f"\n--- {name} ---"]
    windows = [
        ("Inainte de atac  (0-15s)", 0, ATTACK_START),
        ("In timpul atacului (15-45s)", ATTACK_START, ATTACK_END),
        ("Dupa atac (45-60s)", ATTACK_END, 999),
    ]
    for label, lo, hi in windows:
        st = window_stats(rows, lo, hi)
        if st is None:
            lines.append(f"{label}: fara date")
            continue
        lines.append(
            f"{label}: {st['n']} cereri | succes={st['success_rate']:.1f}% | "
            f"latenta medie={st['avg_latency']:.1f}ms | p95={st['p95_latency']:.1f}ms | "
            f"max={st['max_latency']:.1f}ms"
        )
    return "\n".join(lines)


def make_plot(baseline, protected):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("[compare_results] matplotlib nu e instalat - sar peste grafic "
              "(poti rula: pip install matplotlib)")
        return

    fig, ax = plt.subplots(figsize=(10, 5))

    for rows, label, color in [(baseline, "Vulnerabil (fara protectie)", "tab:red"),
                                 (protected, "Protejat (rate limiting + coada)", "tab:green")]:
        t = [r["t"] for r in rows]
        lat = [r["latency_ms"] if (r["connected"] and r["ok"]) else None for r in rows]
        # inlocuim cererile esuate cu o valoare mare, ca sa se vada pe grafic
        lat_plot = [l if l is not None else max([x for x in lat if x is not None] or [0]) * 1.1 + 50
                    for l in lat]
        ax.plot(t, lat_plot, label=label, color=color, linewidth=1.2, marker="o", markersize=2)

    ax.axvspan(ATTACK_START, ATTACK_END, color="gray", alpha=0.15, label="Fereastra de atac")
    ax.set_xlabel("Timp (secunde)")
    ax.set_ylabel("Latenta cerere legitima (ms)")
    ax.set_title("Degradarea performantei in timpul atacului DoS: vulnerabil vs. protejat")
    ax.legend()
    ax.grid(True, alpha=0.3)

    out_path = os.path.join(RESULTS_DIR, "comparatie_latenta.png")
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    print(f"[compare_results] Grafic salvat in: {out_path}")


def main():
    baseline_path = os.path.join(RESULTS_DIR, "legit_baseline.csv")
    protected_path = os.path.join(RESULTS_DIR, "legit_protected.csv")

    if not os.path.exists(baseline_path) or not os.path.exists(protected_path):
        print("Lipsesc fisiere de rezultate. Ruleaza mai intai:\n"
              "  python run_experiment.py baseline\n"
              "  python run_experiment.py protected")
        return

    baseline = load(baseline_path)
    protected = load(protected_path)

    report = "RAPORT COMPARATIV - Atac DoS asupra server-ului PLC simulat\n"
    report += "=" * 60
    report += report_for("Server VULNERABIL (fara protectii)", baseline)
    report += "\n"
    report += report_for("Server PROTEJAT (rate limiting + coada marginita)", protected)

    print(report)

    with open(os.path.join(RESULTS_DIR, "raport_comparativ.txt"), "w", encoding="utf-8") as f:
        f.write(report)

    make_plot(baseline, protected)


if __name__ == "__main__":
    main()
