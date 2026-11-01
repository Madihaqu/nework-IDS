"""
Helper script to generate a standalone CIC-IDS2017 sample CSV file.
Usage:
    python generate_dataset.py --samples 5000 --output cicids2017_sample.csv
"""

import argparse
import pandas as pd
import numpy as np

def generate_csv(n_samples: int = 5000, output_file: str = "cicids2017_sample.csv", seed: int = 42):
    np.random.seed(seed)
    n_benign = int(n_samples * 0.65)
    n_ddos = int(n_samples * 0.15)
    n_portscan = int(n_samples * 0.12)
    n_unseen = n_samples - (n_benign + n_ddos + n_portscan)

    records = []

    # 1. BENIGN
    for _ in range(n_benign):
        dur = np.random.exponential(scale=1200) + 50
        fwd = int(np.random.poisson(lam=8) + 1)
        bwd = int(np.random.poisson(lam=10) + 1)
        f_len = np.random.normal(loc=320, scale=80)
        b_len = np.random.normal(loc=650, scale=120)
        tot_b = (fwd * f_len) + (bwd * b_len)
        records.append({
            "flow_duration_ms": max(dur, 10.0),
            "total_fwd_packets": fwd,
            "total_bwd_packets": bwd,
            "fwd_pkt_len_mean": max(f_len, 40.0),
            "bwd_pkt_len_mean": max(b_len, 40.0),
            "flow_bytes_per_sec": max((tot_b / (dur / 1000.0)), 100.0),
            "flow_pkts_per_sec": max(((fwd + bwd) / (dur / 1000.0)), 1.0),
            "fwd_iat_mean": np.random.exponential(scale=120) + 10,
            "bwd_iat_mean": np.random.exponential(scale=110) + 10,
            "syn_flag_count": np.random.choice([0, 1], p=[0.7, 0.3]),
            "ack_flag_count": np.random.choice([0, 1], p=[0.1, 0.9]),
            "avg_packet_size": tot_b / max(fwd + bwd, 1),
            "true_label": "BENIGN"
        })

    # 2. DDOS
    for _ in range(n_ddos):
        dur = np.random.uniform(20, 400)
        fwd = int(np.random.uniform(150, 600))
        bwd = int(np.random.choice([0, 1, 2], p=[0.7, 0.2, 0.1]))
        f_len = np.random.uniform(54, 80)
        b_len = 40.0 if bwd > 0 else 0.0
        tot_b = (fwd * f_len) + (bwd * b_len)
        records.append({
            "flow_duration_ms": dur,
            "total_fwd_packets": fwd,
            "total_bwd_packets": bwd,
            "fwd_pkt_len_mean": f_len,
            "bwd_pkt_len_mean": b_len,
            "flow_bytes_per_sec": (tot_b / (dur / 1000.0)),
            "flow_pkts_per_sec": ((fwd + bwd) / (dur / 1000.0)),
            "fwd_iat_mean": np.random.uniform(0.1, 3.0),
            "bwd_iat_mean": 0.0,
            "syn_flag_count": 1,
            "ack_flag_count": 0,
            "avg_packet_size": tot_b / max(fwd + bwd, 1),
            "true_label": "DDoS"
        })

    # 3. PORTSCAN
    for _ in range(n_portscan):
        dur = np.random.uniform(1.0, 15.0)
        fwd = int(np.random.choice([1, 2, 3], p=[0.8, 0.15, 0.05]))
        bwd = int(np.random.choice([0, 1], p=[0.85, 0.15]))
        f_len = np.random.uniform(40, 60)
        b_len = 40.0 if bwd > 0 else 0.0
        tot_b = (fwd * f_len) + (bwd * b_len)
        records.append({
            "flow_duration_ms": dur,
            "total_fwd_packets": fwd,
            "total_bwd_packets": bwd,
            "fwd_pkt_len_mean": f_len,
            "bwd_pkt_len_mean": b_len,
            "flow_bytes_per_sec": (tot_b / (dur / 1000.0)),
            "flow_pkts_per_sec": ((fwd + bwd) / (dur / 1000.0)),
            "fwd_iat_mean": np.random.uniform(0.2, 5.0),
            "bwd_iat_mean": 0.0,
            "syn_flag_count": 1,
            "ack_flag_count": 0,
            "avg_packet_size": tot_b / max(fwd + bwd, 1),
            "true_label": "PortScan"
        })

    # 4. UNSEEN ZERO-DAY
    for _ in range(n_unseen):
        dur = np.random.uniform(5000, 18000)
        fwd = int(np.random.uniform(40, 120))
        bwd = int(np.random.uniform(5, 25))
        f_len = np.random.uniform(1100, 1480)
        b_len = np.random.uniform(60, 90)
        tot_b = (fwd * f_len) + (bwd * b_len)
        records.append({
            "flow_duration_ms": dur,
            "total_fwd_packets": fwd,
            "total_bwd_packets": bwd,
            "fwd_pkt_len_mean": f_len,
            "bwd_pkt_len_mean": b_len,
            "flow_bytes_per_sec": (tot_b / (dur / 1000.0)),
            "flow_pkts_per_sec": ((fwd + bwd) / (dur / 1000.0)),
            "fwd_iat_mean": np.random.uniform(350, 900),
            "bwd_iat_mean": np.random.uniform(400, 1200),
            "syn_flag_count": 0,
            "ack_flag_count": 1,
            "avg_packet_size": tot_b / max(fwd + bwd, 1),
            "true_label": "Unseen_Attack"
        })

    df = pd.DataFrame(records).sample(frac=1.0, random_state=seed).reset_index(drop=True)
    df.to_csv(output_file, index=False)
    print(f"Generated {len(df)} records in '{output_file}' successfully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic CIC-IDS2017 dataset CSV.")
    parser.add_argument("--samples", type=int, default=4000, help="Number of records to generate")
    parser.add_argument("--output", type=str, default="cicids2017_sample.csv", help="Output file path")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()
    generate_csv(args.samples, args.output, args.seed)
