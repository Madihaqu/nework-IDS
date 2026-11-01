import React from 'react';
import { ModelMetrics } from '../types/nids';
import { Activity, ShieldAlert, AlertTriangle, Crosshair, HeartPulse, Zap } from 'lucide-react';

interface MetricsCardsProps {
  metrics: ModelMetrics;
  isStreaming?: boolean;
}

export const MetricsCards: React.FC<MetricsCardsProps> = ({ metrics, isStreaming }) => {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
      {/* 1. Total Flows Processed */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 border-l-4 border-l-blue-500 relative overflow-hidden flex flex-col justify-between">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            Total Flows Processed
          </span>
          <Activity className="w-4 h-4 text-blue-400" />
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-slate-100">
            {metrics.totalFlows.toLocaleString()}
          </span>
          <span className="text-xs text-slate-400">flows</span>
        </div>
        <div className="mt-1 flex items-center justify-between text-[11px] text-slate-400">
          <span>{metrics.normalFlows.toLocaleString()} normal</span>
          {isStreaming && (
            <span className="text-cyan-400 font-mono text-[10px] animate-pulse">
              LIVE INGESTING
            </span>
          )}
        </div>
      </div>

      {/* 2. Known Threats Detected */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 border-l-4 border-l-rose-500 relative overflow-hidden flex flex-col justify-between">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            Known Threats Detected
          </span>
          <ShieldAlert className="w-4 h-4 text-rose-400" />
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-rose-400">
            {metrics.knownAttacks.toLocaleString()}
          </span>
          <span className="text-xs text-rose-400/80 font-mono">
            ({((metrics.knownAttacks / Math.max(metrics.totalFlows, 1)) * 100).toFixed(1)}%)
          </span>
        </div>
        <div className="mt-1 text-[11px] text-slate-400">
          Supervised RF: DDoS &amp; PortScans
        </div>
      </div>

      {/* 3. Zero-Day Anomalies */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 border-l-4 border-l-amber-500 relative overflow-hidden flex flex-col justify-between">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            Zero-Day Anomalies
          </span>
          <AlertTriangle className="w-4 h-4 text-amber-400" />
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-amber-400">
            {metrics.anomaliesFlagged.toLocaleString()}
          </span>
          <span className="text-xs text-amber-400/80 font-mono">
            ({((metrics.anomaliesFlagged / Math.max(metrics.totalFlows, 1)) * 100).toFixed(1)}%)
          </span>
        </div>
        <div className="mt-1 text-[11px] text-slate-400">
          Unsupervised IF: Novel Outliers
        </div>
      </div>

      {/* 4. System Health & Wire Latency */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 border-l-4 border-l-cyan-500 relative overflow-hidden flex flex-col justify-between">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            System Health
          </span>
          <HeartPulse className="w-4 h-4 text-cyan-400" />
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-xl font-bold font-mono text-cyan-400 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            {metrics.systemHealth?.status || 'OPTIMAL'}
          </span>
          <span className="text-[10px] text-slate-400 font-mono">
            {metrics.systemHealth?.uptimePercent || 99.98}%
          </span>
        </div>
        <div className="mt-1 text-[11px] text-slate-400 flex items-center justify-between">
          <span>Wire Latency:</span>
          <span className="font-mono text-slate-300 font-medium">
            {metrics.systemHealth?.latencyMs || 1.84} ms
          </span>
        </div>
      </div>

      {/* 5. Hybrid Model Accuracy & Zero-Day Rate */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 border-l-4 border-l-emerald-500 relative overflow-hidden flex flex-col justify-between">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            Model Accuracy
          </span>
          <Crosshair className="w-4 h-4 text-emerald-400" />
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-emerald-400">
            {metrics.overallAccuracy.toFixed(1)}%
          </span>
          <span className="text-xs text-emerald-400/80 font-mono">
            (Zero-Day: {metrics.zeroDayCaptureRate.toFixed(0)}%)
          </span>
        </div>
        <div className="mt-1 text-[11px] text-slate-400">
          False alarm rate: {metrics.benignFalseAlarmRate.toFixed(1)}%
        </div>
      </div>
    </div>
  );
};
