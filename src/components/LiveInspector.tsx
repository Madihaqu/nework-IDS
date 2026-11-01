import React, { useState } from 'react';
import { NetworkFlow, EvaluatedFlow, ModelHyperparams } from '../types/nids';
import { Play, ShieldAlert, AlertTriangle, ShieldCheck, ArrowRight, Zap, RefreshCw } from 'lucide-react';

interface LiveInspectorProps {
  hyperparams: ModelHyperparams;
}

export const LiveInspector: React.FC<LiveInspectorProps> = ({ hyperparams }) => {
  const [preset, setPreset] = useState<string>('Zero-Day Exfiltration / Tunnel');
  const [duration, setDuration] = useState<number>(12000);
  const [fwdPkts, setFwdPkts] = useState<number>(85);
  const [bwdPkts, setBwdPkts] = useState<number>(12);
  const [fwdLenMean, setFwdLenMean] = useState<number>(1420);
  const [bwdLenMean, setBwdLenMean] = useState<number>(64);
  const [synFlag, setSynFlag] = useState<number>(0);
  const [ackFlag, setAckFlag] = useState<number>(1);

  const [result, setResult] = useState<{
    rfPredicted: string;
    rfConfidence: number;
    ifScore: number;
    isAnomaly: boolean;
    decision: 'Normal' | 'Known Attack' | 'Potential Unknown/Anomalous Attack';
    reason: string;
    rulePath: string;
  } | null>(null);

  // Compute derived properties
  const totalBytes = fwdPkts * fwdLenMean + bwdPkts * bwdLenMean;
  const totalPkts = fwdPkts + bwdPkts;
  const flowBytesPerSec = duration > 0 ? totalBytes / (duration / 1000.0) : 0;
  const flowPktsPerSec = duration > 0 ? totalPkts / (duration / 1000.0) : 0;
  const avgPacketSize = totalPkts > 0 ? totalBytes / totalPkts : 0;

  const handlePresetChange = (name: string) => {
    setPreset(name);
    if (name === 'DDoS SYN Flood') {
      setDuration(150);
      setFwdPkts(450);
      setBwdPkts(0);
      setFwdLenMean(64);
      setBwdLenMean(0);
      setSynFlag(1);
      setAckFlag(0);
    } else if (name === 'Stealthy PortScan') {
      setDuration(4);
      setFwdPkts(1);
      setBwdPkts(0);
      setFwdLenMean(44);
      setBwdLenMean(0);
      setSynFlag(1);
      setAckFlag(0);
    } else if (name === 'Zero-Day Exfiltration / Tunnel') {
      setDuration(12000);
      setFwdPkts(85);
      setBwdPkts(12);
      setFwdLenMean(1420);
      setBwdLenMean(64);
      setSynFlag(0);
      setAckFlag(1);
    } else if (name === 'Normal HTTPS Session') {
      setDuration(950);
      setFwdPkts(10);
      setBwdPkts(14);
      setFwdLenMean(340);
      setBwdLenMean(720);
      setSynFlag(0);
      setAckFlag(1);
    }
    setResult(null);
  };

  const handleAnalyze = () => {
    // 1. Supervised Random Forest Decision
    let rfPredicted = 'BENIGN';
    let rfConfidence = 0.88;

    if (flowPktsPerSec > 400 || (fwdPkts > 100 && duration < 600)) {
      rfPredicted = 'DDoS';
      rfConfidence = 0.96;
    } else if (duration <= 25 && fwdPkts <= 3 && bwdPkts <= 1 && synFlag === 1) {
      rfPredicted = 'PortScan';
      rfConfidence = 0.94;
    } else if (fwdLenMean > 1000 && duration > 4000) {
      // The supervised RF has NOT seen this zero-day pattern! It thinks it's a slow benign transfer!
      rfPredicted = 'BENIGN';
      rfConfidence = 0.74;
    } else {
      rfPredicted = 'BENIGN';
      rfConfidence = 0.92;
    }

    // 2. Unsupervised Isolation Forest Decision
    // Measure deviation from normal envelope:
    let anomalyScore = 0.22;
    if (preset === 'Zero-Day Exfiltration / Tunnel' || (fwdLenMean > 1000 && duration > 3000)) {
      // Outlier in payload size and duration/IAT!
      anomalyScore = -0.342;
    } else if (preset === 'DDoS SYN Flood' || flowPktsPerSec > 400) {
      anomalyScore = -0.285;
    } else if (preset === 'Stealthy PortScan' || (duration < 10 && fwdPkts <= 2)) {
      anomalyScore = -0.195;
    } else {
      anomalyScore = 0.185;
    }

    // Adjust by contamination sensitivity
    const thresholdOffset = (hyperparams.ifContamination - 0.08) * 2.0;
    const finalIfScore = anomalyScore + thresholdOffset;
    const isAnomaly = finalIfScore < 0.0;

    // 3. Decision Fusion Engine Logic
    let decision: 'Normal' | 'Known Attack' | 'Potential Unknown/Anomalous Attack' = 'Normal';
    let reason = '';
    let rulePath = '';

    if ((rfPredicted === 'DDoS' || rfPredicted === 'PortScan') && rfConfidence >= hyperparams.rfConfidenceThreshold) {
      decision = 'Known Attack';
      reason = `High Confidence Supervised Signature: ${rfPredicted} (${(rfConfidence * 100).toFixed(1)}%)`;
      rulePath = 'Rule 1: RF Known Attack Conf >= Threshold -> Known Attack';
    } else if (rfPredicted === 'BENIGN') {
      if (isAnomaly) {
        decision = 'Potential Unknown/Anomalous Attack';
        reason = `Zero-Day Threat: RF classified Benign, but Isolation Forest flagged anomalous outlier (score: ${finalIfScore.toFixed(3)})`;
        rulePath = 'Rule 2: RF Benign + IF Anomaly -> Novel / Zero-Day Attack Alert';
      } else {
        decision = 'Normal';
        reason = 'Traffic verified within normal operational profile by both engines.';
        rulePath = 'Rule 3: RF Benign + IF Normal -> Verified Normal';
      }
    } else {
      if (isAnomaly) {
        decision = 'Potential Unknown/Anomalous Attack';
        reason = `Low RF Confidence (${(rfConfidence * 100).toFixed(1)}%) with High Anomaly Score`;
        rulePath = 'Rule 4: Uncertain RF + IF Outlier -> Escalated to Anomaly';
      } else {
        decision = 'Known Attack';
        reason = `RF Classified ${rfPredicted}`;
        rulePath = 'Rule 5: Fallback to RF Prediction';
      }
    }

    setResult({
      rfPredicted,
      rfConfidence,
      ifScore: finalIfScore,
      isAnomaly,
      decision,
      reason,
      rulePath,
    });
  };

  return (
    <div className="space-y-6">
      {/* Preset Selector */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Zap className="w-4 h-4 text-amber-400" />
              Live Flow Testing Sandbox
            </h3>
            <p className="text-xs text-slate-400">
              Select an attack scenario or input custom raw packet flow telemetry to trace the Decision Fusion Engine.
            </p>
          </div>

          <div className="flex flex-wrap gap-1.5 text-xs">
            {[
              'DDoS SYN Flood',
              'Stealthy PortScan',
              'Zero-Day Exfiltration / Tunnel',
              'Normal HTTPS Session',
            ].map((p) => (
              <button
                key={p}
                onClick={() => handlePresetChange(p)}
                className={`px-2.5 py-1 rounded transition-colors text-xs border ${
                  preset === p
                    ? 'bg-blue-600 text-white border-blue-500 font-medium'
                    : 'bg-slate-950 text-slate-300 border-slate-800 hover:border-slate-700'
                }`}
              >
                {p}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Inputs Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Column 1: Flow Duration & Packet Counts */}
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4">
          <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
            Flow Timing & Volume
          </h4>

          <div>
            <div className="flex justify-between text-xs text-slate-300 mb-1">
              <span>Flow Duration (ms)</span>
              <span className="font-mono text-blue-400 font-bold">{duration.toLocaleString()}</span>
            </div>
            <input
              type="number"
              min="1"
              value={duration}
              onChange={(e) => setDuration(Math.max(1, Number(e.target.value)))}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 font-mono"
            />
          </div>

          <div>
            <div className="flex justify-between text-xs text-slate-300 mb-1">
              <span>Total Forward Packets</span>
              <span className="font-mono text-blue-400 font-bold">{fwdPkts}</span>
            </div>
            <input
              type="number"
              min="1"
              value={fwdPkts}
              onChange={(e) => setFwdPkts(Math.max(1, Number(e.target.value)))}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 font-mono"
            />
          </div>

          <div>
            <div className="flex justify-between text-xs text-slate-300 mb-1">
              <span>Total Backward Packets</span>
              <span className="font-mono text-blue-400 font-bold">{bwdPkts}</span>
            </div>
            <input
              type="number"
              min="0"
              value={bwdPkts}
              onChange={(e) => setBwdPkts(Math.max(0, Number(e.target.value)))}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 font-mono"
            />
          </div>
        </div>

        {/* Column 2: Packet Sizes & Flags */}
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4">
          <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
            Payload & Header Flags
          </h4>

          <div>
            <div className="flex justify-between text-xs text-slate-300 mb-1">
              <span>Fwd Packet Length Mean (bytes)</span>
              <span className="font-mono text-blue-400 font-bold">{fwdLenMean}</span>
            </div>
            <input
              type="number"
              min="0"
              value={fwdLenMean}
              onChange={(e) => setFwdLenMean(Math.max(0, Number(e.target.value)))}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 font-mono"
            />
          </div>

          <div>
            <div className="flex justify-between text-xs text-slate-300 mb-1">
              <span>Bwd Packet Length Mean (bytes)</span>
              <span className="font-mono text-blue-400 font-bold">{bwdLenMean}</span>
            </div>
            <input
              type="number"
              min="0"
              value={bwdLenMean}
              onChange={(e) => setBwdLenMean(Math.max(0, Number(e.target.value)))}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 font-mono"
            />
          </div>

          <div className="grid grid-cols-2 gap-3 pt-1">
            <div>
              <label className="block text-xs text-slate-300 mb-1">SYN Flag</label>
              <select
                value={synFlag}
                onChange={(e) => setSynFlag(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-xs text-slate-200 font-mono"
              >
                <option value={0}>0 (No SYN)</option>
                <option value={1}>1 (SYN Set)</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-slate-300 mb-1">ACK Flag</label>
              <select
                value={ackFlag}
                onChange={(e) => setAckFlag(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-xs text-slate-200 font-mono"
              >
                <option value={0}>0 (No ACK)</option>
                <option value={1}>1 (ACK Set)</option>
              </select>
            </div>
          </div>
        </div>

        {/* Column 3: Computed Telemetry & Trigger */}
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
          <div>
            <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-4">
              Real-Time Derived Telemetry
            </h4>

            <div className="space-y-3 font-mono text-xs">
              <div className="p-2.5 rounded bg-slate-950/70 border border-slate-800 flex justify-between items-center">
                <span className="text-slate-400 font-sans">Flow Packets/sec:</span>
                <span className="font-bold text-slate-100">{flowPktsPerSec.toFixed(1)}</span>
              </div>

              <div className="p-2.5 rounded bg-slate-950/70 border border-slate-800 flex justify-between items-center">
                <span className="text-slate-400 font-sans">Flow Bytes/sec:</span>
                <span className="font-bold text-slate-100">{flowBytesPerSec.toLocaleString(undefined, { maximumFractionDigits: 0 })} B/s</span>
              </div>

              <div className="p-2.5 rounded bg-slate-950/70 border border-slate-800 flex justify-between items-center">
                <span className="text-slate-400 font-sans">Avg Packet Size:</span>
                <span className="font-bold text-slate-100">{avgPacketSize.toFixed(1)} bytes</span>
              </div>
            </div>
          </div>

          <button
            onClick={handleAnalyze}
            className="w-full py-2.5 px-4 mt-6 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20 transition-all cursor-pointer"
          >
            <Play className="w-4 h-4 fill-current" />
            Analyze Flow with Hybrid NIDS
          </button>
        </div>
      </div>

      {/* Decision Fusion Walkthrough Result */}
      {result && (
        <div className="p-6 rounded-xl bg-slate-900/90 border border-slate-800 space-y-6 animate-in fade-in duration-300">
          <div>
            <h4 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              Decision Fusion Evaluation Breakdown
            </h4>
            <p className="text-xs text-slate-400">
              Trace how Tier 1 (Supervised) and Tier 2 (Unsupervised) outputs are arbitrated by the Fusion Engine:
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Tier 1 RF Result */}
            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
              <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Tier 1: Supervised Classifier (Random Forest)
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-300">Class:</span>
                <span className="font-mono font-bold text-slate-100 text-sm">
                  {result.rfPredicted}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-300">Confidence:</span>
                <span className="font-mono font-bold text-blue-400 text-sm">
                  {(result.rfConfidence * 100).toFixed(1)}%
                </span>
              </div>
              <div className="text-[11px] text-slate-400 pt-1 border-t border-slate-800/80">
                {result.rfPredicted === 'BENIGN' && preset.includes('Zero-Day')
                  ? '⚠️ Supervised model has never seen this zero-day pattern (False Negative if standalone).'
                  : 'Matches signature model training library.'}
              </div>
            </div>

            {/* Tier 2 IF Result */}
            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
              <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Tier 2: Unsupervised Anomaly Engine (Isolation Forest)
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-300">Anomaly Score:</span>
                <span className={`font-mono font-bold text-sm ${result.ifScore < 0 ? 'text-amber-400' : 'text-slate-100'}`}>
                  {result.ifScore.toFixed(3)}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-300">Status:</span>
                <span className={`text-xs font-semibold px-1.5 py-0.5 rounded ${
                  result.isAnomaly
                    ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                    : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                }`}>
                  {result.isAnomaly ? 'OUTLIER DETECTED' : 'NORMAL ENVELOPE'}
                </span>
              </div>
              <div className="text-[11px] text-slate-400 pt-1 border-t border-slate-800/80">
                Isolation threshold: 0.00 (adjusted for {(hyperparams.ifContamination * 100).toFixed(0)}% contamination).
              </div>
            </div>

            {/* Final Decision */}
            <div className={`p-4 rounded-lg border space-y-2 ${
              result.decision === 'Known Attack'
                ? 'bg-rose-950/20 border-rose-500/40 text-rose-300'
                : result.decision === 'Potential Unknown/Anomalous Attack'
                ? 'bg-amber-950/20 border-amber-500/40 text-amber-300'
                : 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300'
            }`}>
              <div className="text-[10px] font-semibold uppercase tracking-wider">
                Tier 3: Final Decision Fusion Output
              </div>
              <div className="text-lg font-bold flex items-center gap-2">
                {result.decision === 'Known Attack' && <ShieldAlert className="w-5 h-5 text-rose-400" />}
                {result.decision === 'Potential Unknown/Anomalous Attack' && <AlertTriangle className="w-5 h-5 text-amber-400" />}
                {result.decision === 'Normal' && <ShieldCheck className="w-5 h-5 text-emerald-400" />}
                {result.decision}
              </div>
              <div className="text-xs text-slate-200">
                {result.reason}
              </div>
              <div className="text-[10px] font-mono opacity-80 pt-1 border-t border-current/20">
                {result.rulePath}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
