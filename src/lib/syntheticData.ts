import { NetworkFlow, FlowClass } from '../types/nids';

// Pseudo-random generator with seed support for reproducible CSE capstone runs
function createPRNG(seed: number) {
  let s = seed % 2147483647;
  if (s <= 0) s += 2147483646;
  return () => {
    s = (s * 16807) % 2147483647;
    return (s - 1) / 2147483646;
  };
}

function randNormal(rng: () => number, mean: number, std: number): number {
  const u1 = Math.max(rng(), 1e-7);
  const u2 = rng();
  const z0 = Math.sqrt(-2.0 * Math.log(u1)) * Math.cos(2.0 * Math.PI * u2);
  return mean + z0 * std;
}

function randExponential(rng: () => number, scale: number): number {
  const u = Math.max(rng(), 1e-7);
  return -scale * Math.log(u);
}

export function generateSyntheticFlows(nSamples: number = 3000, seed: number = 42): NetworkFlow[] {
  const rng = createPRNG(seed);

  const nBenign = Math.floor(nSamples * 0.65);
  const nDDoS = Math.floor(nSamples * 0.15);
  const nPortScan = Math.floor(nSamples * 0.12);
  const nUnseen = nSamples - (nBenign + nDDoS + nPortScan);

  const flows: NetworkFlow[] = [];
  let idCounter = 1;

  // 1. BENIGN FLOWS (Regular Web, API, Database traffic)
  for (let i = 0; i < nBenign; i++) {
    const duration = Math.max(randExponential(rng, 1200) + 50, 10.0);
    const fwdPkts = Math.max(1, Math.round(rng() * 15 + 2));
    const bwdPkts = Math.max(1, Math.round(rng() * 20 + 2));
    const fwdMean = Math.max(40.0, randNormal(rng, 320, 75));
    const bwdMean = Math.max(40.0, randNormal(rng, 650, 110));
    const totBytes = fwdPkts * fwdMean + bwdPkts * bwdMean;
    const durSec = duration / 1000.0;

    flows.push({
      id: `FLOW-BENIGN-${idCounter++}`,
      flow_duration_ms: duration,
      total_fwd_packets: fwdPkts,
      total_bwd_packets: bwdPkts,
      fwd_pkt_len_mean: fwdMean,
      bwd_pkt_len_mean: bwdMean,
      flow_bytes_per_sec: Math.max(totBytes / durSec, 100.0),
      flow_pkts_per_sec: Math.max((fwdPkts + bwdPkts) / durSec, 1.0),
      fwd_iat_mean: randExponential(rng, 120) + 10,
      bwd_iat_mean: randExponential(rng, 110) + 10,
      syn_flag_count: rng() < 0.3 ? 1 : 0,
      ack_flag_count: rng() < 0.9 ? 1 : 0,
      avg_packet_size: totBytes / (fwdPkts + bwdPkts),
      true_label: 'BENIGN',
    });
  }

  // 2. DDOS (High frequency SYN/UDP volumetric flood)
  for (let i = 0; i < nDDoS; i++) {
    const duration = 20 + rng() * 380;
    const fwdPkts = Math.round(150 + rng() * 450);
    const bwdPkts = rng() < 0.7 ? 0 : rng() < 0.9 ? 1 : 2;
    const fwdMean = 54 + rng() * 26;
    const bwdMean = bwdPkts > 0 ? 40.0 : 0.0;
    const totBytes = fwdPkts * fwdMean + bwdPkts * bwdMean;
    const durSec = duration / 1000.0;

    flows.push({
      id: `FLOW-DDOS-${idCounter++}`,
      flow_duration_ms: duration,
      total_fwd_packets: fwdPkts,
      total_bwd_packets: bwdPkts,
      fwd_pkt_len_mean: fwdMean,
      bwd_pkt_len_mean: bwdMean,
      flow_bytes_per_sec: totBytes / durSec,
      flow_pkts_per_sec: (fwdPkts + bwdPkts) / durSec,
      fwd_iat_mean: 0.1 + rng() * 2.9,
      bwd_iat_mean: 0.0,
      syn_flag_count: 1,
      ack_flag_count: 0,
      avg_packet_size: totBytes / (fwdPkts + bwdPkts),
      true_label: 'DDoS',
    });
  }

  // 3. PORTSCAN (Rapid multi-port reconnaissance probe)
  for (let i = 0; i < nPortScan; i++) {
    const duration = 1.0 + rng() * 14.0;
    const fwdPkts = rng() < 0.8 ? 1 : rng() < 0.95 ? 2 : 3;
    const bwdPkts = rng() < 0.85 ? 0 : 1;
    const fwdMean = 40.0 + rng() * 20.0;
    const bwdMean = bwdPkts > 0 ? 40.0 : 0.0;
    const totBytes = fwdPkts * fwdMean + bwdPkts * bwdMean;
    const durSec = duration / 1000.0;

    flows.push({
      id: `FLOW-SCAN-${idCounter++}`,
      flow_duration_ms: duration,
      total_fwd_packets: fwdPkts,
      total_bwd_packets: bwdPkts,
      fwd_pkt_len_mean: fwdMean,
      bwd_pkt_len_mean: bwdMean,
      flow_bytes_per_sec: totBytes / durSec,
      flow_pkts_per_sec: (fwdPkts + bwdPkts) / durSec,
      fwd_iat_mean: 0.2 + rng() * 4.8,
      bwd_iat_mean: 0.0,
      syn_flag_count: 1,
      ack_flag_count: 0,
      avg_packet_size: totBytes / (fwdPkts + bwdPkts),
      true_label: 'PortScan',
    });
  }

  // 4. UNSEEN / ZERO-DAY ATTACK (Novel DNS Tunneling / Covert Data Exfiltration)
  for (let i = 0; i < nUnseen; i++) {
    const duration = 5000 + rng() * 13000;
    const fwdPkts = Math.round(40 + rng() * 80);
    const bwdPkts = Math.round(5 + rng() * 20);
    const fwdMean = 1100 + rng() * 380; // abnormally large chunk sizes
    const bwdMean = 60 + rng() * 30;
    const totBytes = fwdPkts * fwdMean + bwdPkts * bwdMean;
    const durSec = duration / 1000.0;

    flows.push({
      id: `FLOW-UNSEEN-${idCounter++}`,
      flow_duration_ms: duration,
      total_fwd_packets: fwdPkts,
      total_bwd_packets: bwdPkts,
      fwd_pkt_len_mean: fwdMean,
      bwd_pkt_len_mean: bwdMean,
      flow_bytes_per_sec: totBytes / durSec,
      flow_pkts_per_sec: (fwdPkts + bwdPkts) / durSec,
      fwd_iat_mean: 350 + rng() * 550, // strange slow heartbeat
      bwd_iat_mean: 400 + rng() * 800,
      syn_flag_count: 0,
      ack_flag_count: 1,
      avg_packet_size: totBytes / (fwdPkts + bwdPkts),
      true_label: 'Unseen_Attack',
    });
  }

  // Shuffle array using Fisher-Yates with PRNG
  for (let i = flows.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [flows[i], flows[j]] = [flows[j], flows[i]];
  }

  return flows;
}

export function parseCSVToFlows(csvText: string): NetworkFlow[] {
  const lines = csvText.trim().split(/\r?\n/);
  if (lines.length < 2) return [];

  const headers = lines[0].split(',').map((h) => h.trim().toLowerCase());
  const flows: NetworkFlow[] = [];

  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split(',').map((c) => c.trim());
    if (cols.length < headers.length) continue;

    const getNum = (name: string, fallback: number) => {
      const idx = headers.indexOf(name);
      if (idx === -1) return fallback;
      const val = parseFloat(cols[idx]);
      return isNaN(val) ? fallback : val;
    };

    const getStr = (name: string, fallback: string) => {
      const idx = headers.indexOf(name);
      return idx !== -1 ? cols[idx] : fallback;
    };

    const rawLabel = getStr('true_label', getStr('label', 'BENIGN'));
    let true_label: FlowClass = 'BENIGN';
    if (rawLabel.toUpperCase().includes('DDOS')) true_label = 'DDoS';
    else if (rawLabel.toUpperCase().includes('SCAN')) true_label = 'PortScan';
    else if (rawLabel.toUpperCase().includes('UNSEEN') || rawLabel.toUpperCase().includes('ZERO')) true_label = 'Unseen_Attack';

    flows.push({
      id: `CSV-FLOW-${i}`,
      flow_duration_ms: getNum('flow_duration_ms', 1000),
      total_fwd_packets: getNum('total_fwd_packets', 10),
      total_bwd_packets: getNum('total_bwd_packets', 10),
      fwd_pkt_len_mean: getNum('fwd_pkt_len_mean', 200),
      bwd_pkt_len_mean: getNum('bwd_pkt_len_mean', 400),
      flow_bytes_per_sec: getNum('flow_bytes_per_sec', 5000),
      flow_pkts_per_sec: getNum('flow_pkts_per_sec', 15),
      fwd_iat_mean: getNum('fwd_iat_mean', 100),
      bwd_iat_mean: getNum('bwd_iat_mean', 100),
      syn_flag_count: Math.round(getNum('syn_flag_count', 0)),
      ack_flag_count: Math.round(getNum('ack_flag_count', 1)),
      avg_packet_size: getNum('avg_packet_size', 300),
      true_label,
    });
  }

  return flows;
}
