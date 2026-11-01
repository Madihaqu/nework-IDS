import React from 'react';
import { ModelMetrics } from '../types/nids';
import { Activity, ShieldAlert, AlertTriangle, Crosshair } from 'lucide-react';

interface MetricsCardsProps {
  metrics: ModelMetrics;
}

export const MetricsCards: React.FC<MetricsCardsProps> = ({ metrics }) => {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* 1. Total Flows */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 border-l-4 border-l-blue-500 relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Total Flows Analyzed
          </span>
          <Activity className="w-4 h-4 text-blue-400" />
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-slate-100">
            {metrics.totalFlows.toLocaleString()}
          </span>
          <span className="text-xs text-slate-400">flows</span>
        </div>
        <div className="mt-1 text-[11px] text-slate-400">
          {(metrics.normalFlows).toLocaleString()} verified normal flows
        </div>
      </div>

      {/* 2. Known Attacks Detected */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 border-l-4 border-l-rose-500 relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Known Attacks Detected
          </span>
          <ShieldAlert className="w-4 h-4 text-rose-400" />
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-rose-400">
            {metrics.knownAttacks.toLocaleString()}
          </span>
          <span className="text-xs text-rose-400/80">
            ({((metrics.knownAttacks / Math.max(metrics.totalFlows, 1)) * 100).toFixed(1)}%)
          </span>
        </div>
        <div className="mt-1 text-[11px] text-slate-400">
          Supervised RF: DDoS & PortScan signatures
        </div>
      </div>

      {/* 3. Anomalies Flagged */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 border-l-4 border-l-amber-500 relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Anomalies Flagged
          </span>
          <AlertTriangle className="w-4 h-4 text-amber-400" />
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-amber-400">
            {metrics.anomaliesFlagged.toLocaleString()}
          </span>
          <span className="text-xs text-amber-400/80">
            ({((metrics.anomaliesFlagged / Math.max(metrics.totalFlows, 1)) * 100).toFixed(1)}%)
          </span>
        </div>
        <div className="mt-1 text-[11px] text-slate-400">
          Unsupervised IF: Zero-day / Unknown outliers
        </div>
      </div>

      {/* 4. Zero-Day Capture Rate */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 border-l-4 border-l-emerald-500 relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Zero-Day Capture Rate
          </span>
          <Crosshair className="w-4 h-4 text-emerald-400" />
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-emerald-400">
            {metrics.zeroDayCaptureRate.toFixed(1)}%
          </span>
          <span className="text-xs text-emerald-400/80">
            ({metrics.zeroDayCaught}/{metrics.zeroDayTotal})
          </span>
        </div>
        <div className="mt-1 text-[11px] text-slate-400">
          False alarm rate on normal: {metrics.benignFalseAlarmRate.toFixed(1)}%
        </div>
      </div>
    </div>
  );
};
