import React, { useState } from 'react';
import { EvaluatedFlow, ModelMetrics } from '../types/nids';
import { PieChart, BarChart2, TrendingUp, Grid, Info } from 'lucide-react';

interface DetectionAnalyticsProps {
  evaluatedFlows: EvaluatedFlow[];
  metrics: ModelMetrics;
}

export const DetectionAnalytics: React.FC<DetectionAnalyticsProps> = ({
  evaluatedFlows,
  metrics,
}) => {
  const [hoveredPoint, setHoveredPoint] = useState<EvaluatedFlow | null>(null);

  // 1. Donut breakdown data
  const total = metrics.totalFlows || 1;
  const normalPct = ((metrics.normalFlows / total) * 100);
  const knownPct = ((metrics.knownAttacks / total) * 100);
  const anomalyPct = ((metrics.anomaliesFlagged / total) * 100);

  // SVG Donut calculation
  const radius = 64;
  const circumference = 2 * Math.PI * radius;
  const strokeNormal = (normalPct / 100) * circumference;
  const strokeKnown = (knownPct / 100) * circumference;
  const strokeAnomaly = (anomalyPct / 100) * circumference;

  // 2. Anomaly score histogram calculation (40 bins)
  const nBins = 24;
  const minScore = -0.6;
  const maxScore = 0.4;
  const binWidth = (maxScore - minScore) / nBins;

  const histogramBins: {
    min: number;
    max: number;
    normalCount: number;
    knownCount: number;
    anomalyCount: number;
  }[] = Array.from({ length: nBins }, (_, i) => ({
    min: minScore + i * binWidth,
    max: minScore + (i + 1) * binWidth,
    normalCount: 0,
    knownCount: 0,
    anomalyCount: 0,
  }));

  for (const f of evaluatedFlows) {
    const binIdx = Math.min(
      Math.max(0, Math.floor((f.if_score - minScore) / binWidth)),
      nBins - 1
    );
    if (f.hybrid_decision === 'Normal') histogramBins[binIdx].normalCount++;
    else if (f.hybrid_decision === 'Known Attack') histogramBins[binIdx].knownCount++;
    else histogramBins[binIdx].anomalyCount++;
  }

  const maxBinHeight = Math.max(
    ...histogramBins.map((b) => b.normalCount + b.knownCount + b.anomalyCount),
    1
  );

  // 3. 2D PCA sampled points for fast, smooth rendering (sample up to 400 points)
  const sampledFlows = evaluatedFlows.slice(0, 450);

  // PCA domain
  const pcaXMin = -4;
  const pcaXMax = 6;
  const pcaYMin = -3;
  const pcaYMax = 5;

  const getPcaColor = (decision: EvaluatedFlow['hybrid_decision']) => {
    switch (decision) {
      case 'Normal':
        return '#10B981'; // Emerald
      case 'Known Attack':
        return '#EF4444'; // Rose
      case 'Potential Unknown/Anomalous Attack':
        return '#F59E0B'; // Amber
    }
  };

  return (
    <div className="space-y-6">
      {/* Row 1: Decision Breakdown & Feature Importance */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Donut Chart */}
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-semibold text-sm text-slate-100 flex items-center gap-2">
                <PieChart className="w-4 h-4 text-blue-400" />
                Decision Breakdown
              </h3>
              <p className="text-xs text-slate-400">
                Proportion of network flows triaged by the hybrid fusion pipeline
              </p>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-8 py-2">
            {/* SVG Donut */}
            <div className="relative w-40 h-40">
              <svg viewBox="0 0 160 160" className="w-full h-full -rotate-90">
                {/* Background Ring */}
                <circle
                  cx="80"
                  cy="80"
                  r={radius}
                  fill="none"
                  stroke="#1E293B"
                  strokeWidth="20"
                />
                {/* Normal */}
                <circle
                  cx="80"
                  cy="80"
                  r={radius}
                  fill="none"
                  stroke="#10B981"
                  strokeWidth="20"
                  strokeDasharray={`${strokeNormal} ${circumference}`}
                  strokeDashoffset="0"
                />
                {/* Known Attack */}
                <circle
                  cx="80"
                  cy="80"
                  r={radius}
                  fill="none"
                  stroke="#EF4444"
                  strokeWidth="20"
                  strokeDasharray={`${strokeKnown} ${circumference}`}
                  strokeDashoffset={-strokeNormal}
                />
                {/* Anomaly / Zero-Day */}
                <circle
                  cx="80"
                  cy="80"
                  r={radius}
                  fill="none"
                  stroke="#F59E0B"
                  strokeWidth="20"
                  strokeDasharray={`${strokeAnomaly} ${circumference}`}
                  strokeDashoffset={-(strokeNormal + strokeKnown)}
                />
              </svg>

              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="text-xs text-slate-400 uppercase font-semibold">Decisions</span>
                <span className="text-xl font-bold font-mono text-slate-100">
                  {metrics.totalFlows}
                </span>
              </div>
            </div>

            {/* Legend */}
            <div className="space-y-3 text-xs w-full sm:w-auto">
              <div className="flex items-center justify-between sm:justify-start gap-3">
                <span className="w-3 h-3 rounded-sm bg-emerald-500 shrink-0" />
                <span className="text-slate-300">Normal Traffic:</span>
                <span className="font-mono font-bold text-slate-100 ml-auto sm:ml-2">
                  {metrics.normalFlows} ({normalPct.toFixed(1)}%)
                </span>
              </div>

              <div className="flex items-center justify-between sm:justify-start gap-3">
                <span className="w-3 h-3 rounded-sm bg-rose-500 shrink-0" />
                <span className="text-slate-300">Known Attacks:</span>
                <span className="font-mono font-bold text-slate-100 ml-auto sm:ml-2">
                  {metrics.knownAttacks} ({knownPct.toFixed(1)}%)
                </span>
              </div>

              <div className="flex items-center justify-between sm:justify-start gap-3">
                <span className="w-3 h-3 rounded-sm bg-amber-500 shrink-0" />
                <span className="text-slate-300">Anomalous / Zero-Day:</span>
                <span className="font-mono font-bold text-slate-100 ml-auto sm:ml-2">
                  {metrics.anomaliesFlagged} ({anomalyPct.toFixed(1)}%)
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Feature Importance Bar Chart */}
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-semibold text-sm text-slate-100 flex items-center gap-2">
                <BarChart2 className="w-4 h-4 text-purple-400" />
                Random Forest Feature Importance
              </h3>
              <p className="text-xs text-slate-400">
                Gini impurity reduction across ensemble decision trees
              </p>
            </div>
          </div>

          <div className="space-y-2.5 pt-1">
            {metrics.featureImportances.slice(0, 6).map((feat, i) => (
              <div key={feat.feature} className="text-xs">
                <div className="flex justify-between text-slate-300 mb-1">
                  <span className="font-medium">{feat.label}</span>
                  <span className="font-mono font-bold text-purple-400">
                    {(feat.importance * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
                  <div
                    className="bg-gradient-to-r from-purple-600 to-indigo-400 h-full rounded-full transition-all duration-500"
                    style={{ width: `${(feat.importance / 0.28) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Row 2: Anomaly Score Histogram & 2D PCA Cluster Map */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Isolation Forest Score Histogram */}
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800">
          <div className="flex items-center justify-between mb-2">
            <div>
              <h3 className="font-semibold text-sm text-slate-100 flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-amber-400" />
                Isolation Forest Anomaly Scores
              </h3>
              <p className="text-xs text-slate-400">
                Scores &lt; 0.0 denote anomalous flows that deviate from normal baseline
              </p>
            </div>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/30">
              Cutoff: 0.00
            </span>
          </div>

          {/* Histogram Chart */}
          <div className="pt-4">
            <div className="h-44 w-full flex items-end gap-1 relative border-b border-slate-800 pb-1">
              {/* Threshold Line at x = 0.0 */}
              <div
                className="absolute top-0 bottom-0 w-0.5 border-l-2 border-dashed border-rose-500 z-10 pointer-events-none"
                style={{
                  left: `${((0.0 - minScore) / (maxScore - minScore)) * 100}%`,
                }}
              >
                <span className="absolute -top-3.5 -left-10 text-[10px] font-mono text-rose-400 bg-slate-950 px-1 rounded border border-rose-500/30">
                  Anomaly Cutoff
                </span>
              </div>

              {histogramBins.map((bin, i) => {
                const totalInBin = bin.normalCount + bin.knownCount + bin.anomalyCount;
                const heightPct = (totalInBin / maxBinHeight) * 100;
                const normalH = (bin.normalCount / Math.max(totalInBin, 1)) * 100;
                const anomalyH = (bin.anomalyCount / Math.max(totalInBin, 1)) * 100;
                const knownH = (bin.knownCount / Math.max(totalInBin, 1)) * 100;

                return (
                  <div
                    key={i}
                    className="flex-1 flex flex-col justify-end h-full group relative"
                  >
                    <div
                      className="w-full flex flex-col justify-end rounded-t-sm overflow-hidden transition-all group-hover:brightness-125"
                      style={{ height: `${Math.max(heightPct, 2)}%` }}
                    >
                      <div className="bg-amber-500" style={{ height: `${anomalyH}%` }} />
                      <div className="bg-rose-500" style={{ height: `${knownH}%` }} />
                      <div className="bg-emerald-500" style={{ height: `${normalH}%` }} />
                    </div>

                    {/* Tooltip on hover */}
                    <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1 hidden group-hover:block z-20 pointer-events-none bg-slate-950 border border-slate-700 text-slate-200 text-[10px] p-2 rounded shadow-lg whitespace-nowrap">
                      <div>Range: [{bin.min.toFixed(2)}, {bin.max.toFixed(2)}]</div>
                      <div className="text-emerald-400">Normal: {bin.normalCount}</div>
                      <div className="text-rose-400">Known: {bin.knownCount}</div>
                      <div className="text-amber-400">Anomalous: {bin.anomalyCount}</div>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="flex justify-between text-[10px] text-slate-400 font-mono mt-1.5">
              <span>{minScore.toFixed(1)} (Highly Anomalous)</span>
              <span>0.0 (Threshold)</span>
              <span>{maxScore.toFixed(1)} (Baseline Normal)</span>
            </div>
          </div>
        </div>

        {/* 2D PCA Cluster Map */}
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800">
          <div className="flex items-center justify-between mb-2">
            <div>
              <h3 className="font-semibold text-sm text-slate-100 flex items-center gap-2">
                <Grid className="w-4 h-4 text-cyan-400" />
                2D PCA Feature Space Representation
              </h3>
              <p className="text-xs text-slate-400">
                Multi-dimensional cluster separation of network flows
              </p>
            </div>
            <span className="text-[10px] text-slate-400 font-mono">
              N={sampledFlows.length}
            </span>
          </div>

          <div className="relative h-44 w-full bg-slate-950/80 rounded border border-slate-800/80 overflow-hidden">
            <svg viewBox="0 0 400 180" className="w-full h-full">
              {/* Grid axes */}
              <line x1="0" y1="90" x2="400" y2="90" stroke="#1E293B" strokeWidth="1" />
              <line x1="200" y1="0" x2="200" y2="180" stroke="#1E293B" strokeWidth="1" />

              {sampledFlows.map((flow) => {
                // Map PCA coords to SVG canvas
                const px = ((flow.pca_x! - pcaXMin) / (pcaXMax - pcaXMin)) * 400;
                const py = 180 - ((flow.pca_y! - pcaYMin) / (pcaYMax - pcaYMin)) * 180;
                const color = getPcaColor(flow.hybrid_decision);

                return (
                  <circle
                    key={flow.id}
                    cx={Math.max(4, Math.min(396, px))}
                    cy={Math.max(4, Math.min(176, py))}
                    r={hoveredPoint?.id === flow.id ? 5 : 2.5}
                    fill={color}
                    opacity={hoveredPoint?.id === flow.id ? 1 : 0.75}
                    className="cursor-pointer transition-all"
                    onMouseEnter={() => setHoveredPoint(flow)}
                    onMouseLeave={() => setHoveredPoint(null)}
                  />
                );
              })}
            </svg>

            {/* Hover details box */}
            {hoveredPoint && (
              <div className="absolute top-2 right-2 bg-slate-950/95 border border-slate-700 p-2 rounded text-[11px] shadow-xl z-10 pointer-events-none">
                <div className="font-bold text-slate-100">{hoveredPoint.id}</div>
                <div className="text-slate-400">Truth: <span className="text-slate-200">{hoveredPoint.true_label}</span></div>
                <div className="text-slate-400">Decision: <span className="font-semibold text-blue-400">{hoveredPoint.hybrid_decision}</span></div>
                <div className="text-slate-400">IF Score: <span className="font-mono text-amber-400">{hoveredPoint.if_score.toFixed(3)}</span></div>
              </div>
            )}
          </div>

          <div className="flex items-center justify-between text-[11px] text-slate-400 mt-2">
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-emerald-500" /> Normal
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-rose-500" /> Known Attack
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-amber-500" /> Unknown Anomaly
              </span>
            </div>
            <span className="text-[10px] font-mono">Hover over dots to inspect</span>
          </div>
        </div>
      </div>

      {/* Row 3: Ground Truth vs Hybrid Decision Evaluation Matrix */}
      <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="font-semibold text-sm text-slate-100 flex items-center gap-2">
              <Grid className="w-4 h-4 text-emerald-400" />
              Hybrid NIDS Confusion Matrix (Evaluation vs Ground Truth)
            </h3>
            <p className="text-xs text-slate-400">
              Evaluates how well the dual-engine pipeline correctly categorizes known attacks and flags unseen zero-day exploits.
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-400">Overall Accuracy:</span>
            <span className="font-bold font-mono text-emerald-400 text-sm">
              {metrics.overallAccuracy.toFixed(1)}%
            </span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[10px]">
                <th className="py-2.5 px-3">Ground Truth Class</th>
                <th className="py-2.5 px-3 text-emerald-400">Predicted Normal</th>
                <th className="py-2.5 px-3 text-rose-400">Predicted Known Attack</th>
                <th className="py-2.5 px-3 text-amber-400">Predicted Unknown Anomaly</th>
                <th className="py-2.5 px-3 text-right">Detection Rate</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {metrics.confusionMatrix.labels.map((label, rowIdx) => {
                const row = metrics.confusionMatrix.matrix[rowIdx];
                const rowSum = row.reduce((a, b) => a + b, 0);

                let rate = 0;
                let isIdealNormal = false;
                let isIdealKnown = false;
                let isIdealZeroDay = false;

                if (label === 'BENIGN') {
                  rate = (row[0] / Math.max(rowSum, 1)) * 100;
                  isIdealNormal = true;
                } else if (label === 'DDoS' || label === 'PortScan') {
                  rate = (row[1] / Math.max(rowSum, 1)) * 100;
                  isIdealKnown = true;
                } else if (label === 'Unseen_Attack') {
                  rate = (row[2] / Math.max(rowSum, 1)) * 100;
                  isIdealZeroDay = true;
                }

                return (
                  <tr key={label} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-2.5 px-3 font-semibold font-sans text-slate-200">
                      {label}
                      {label === 'Unseen_Attack' && (
                        <span className="ml-2 text-[10px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                          Zero-Day Target
                        </span>
                      )}
                    </td>
                    <td className={`py-2.5 px-3 ${isIdealNormal ? 'text-emerald-400 font-bold' : 'text-slate-400'}`}>
                      {row[0]}
                    </td>
                    <td className={`py-2.5 px-3 ${isIdealKnown ? 'text-rose-400 font-bold' : 'text-slate-400'}`}>
                      {row[1]}
                    </td>
                    <td className={`py-2.5 px-3 ${isIdealZeroDay ? 'text-amber-400 font-bold' : 'text-slate-400'}`}>
                      {row[2]}
                    </td>
                    <td className="py-2.5 px-3 text-right font-bold text-slate-100">
                      {rate.toFixed(1)}%
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
