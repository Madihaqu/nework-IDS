import React, { useRef } from 'react';
import { ModelHyperparams } from '../types/nids';
import { Sliders, Database, ShieldAlert, Cpu, RefreshCw, Upload, Play, Square, Activity, Download } from 'lucide-react';

interface SidebarProps {
  hyperparams: ModelHyperparams;
  onChangeHyperparams: (params: Partial<ModelHyperparams>) => void;
  onRegenerateData: () => void;
  onFileUpload: (file: File) => void;
  onDownloadSampleCSV?: () => void;
  dataSourceName: string;
  isStreaming: boolean;
  onToggleStreaming: () => void;
  streamRate: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  hyperparams,
  onChangeHyperparams,
  onRegenerateData,
  onFileUpload,
  onDownloadSampleCSV,
  dataSourceName,
  isStreaming,
  onToggleStreaming,
  streamRate,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      onFileUpload(file);
    }
  };

  return (
    <aside className="w-80 shrink-0 border-r border-slate-800 bg-slate-900/90 flex flex-col h-full overflow-y-auto">
      {/* Brand & Status */}
      <div className="p-4 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="w-9 h-9 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <h1 className="font-bold text-sm text-slate-100 tracking-tight flex items-center gap-2">
              Hybrid NIDS
              <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                ACTIVE
              </span>
            </h1>
            <p className="text-xs text-slate-400">CSE Capstone Engine</p>
          </div>
        </div>
      </div>

      <div className="p-4 space-y-6 flex-1 text-xs">
        {/* Live Packet Streaming Mode */}
        <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
          <div className="flex items-center justify-between mb-1.5">
            <span className="font-semibold text-slate-200 flex items-center gap-1.5">
              <Activity className="w-4 h-4 text-cyan-400" />
              Live PCAP Stream Ingestion
            </span>
            {isStreaming && (
              <span className="flex h-2 w-2 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
              </span>
            )}
          </div>
          <p className="text-slate-400 text-[11px] mb-2.5 leading-snug">
            Simulates wire packets at 10-20 flows/sec into the dual ML pipeline.
          </p>

          {/* Stream Rate Selector */}
          <div className="mb-2.5">
            <div className="flex items-center justify-between text-[11px] text-slate-300 mb-1">
              <span>Ingestion Speed:</span>
              <span className="font-mono text-cyan-400 font-bold">{hyperparams.streamRate || 10} flows/s</span>
            </div>
            <div className="grid grid-cols-3 gap-1">
              {[5, 10, 20].map((rate) => (
                <button
                  key={rate}
                  onClick={() => onChangeHyperparams({ streamRate: rate })}
                  className={`py-1 text-[11px] font-mono rounded border transition-colors ${
                    (hyperparams.streamRate || 10) === rate
                      ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50 font-bold'
                      : 'bg-slate-900 text-slate-400 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  {rate}/sec
                </button>
              ))}
            </div>
          </div>

          <button
            onClick={onToggleStreaming}
            className={`w-full py-2 px-3 rounded font-medium text-xs flex items-center justify-center gap-2 transition-all cursor-pointer ${
              isStreaming
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 hover:bg-rose-500/30'
                : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 hover:bg-cyan-500/30'
            }`}
          >
            {isStreaming ? (
              <>
                <Square className="w-3.5 h-3.5 fill-current" /> Pause Live Feed
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" /> Start Live Ingestion (10-20 flows/s)
              </>
            )}
          </button>
        </div>

        {/* 1. Dataset & Ingestion Pipeline */}
        <div>
          <div className="flex items-center gap-1.5 font-semibold text-slate-200 uppercase tracking-wider text-[11px] mb-3">
            <Database className="w-3.5 h-3.5 text-blue-400" />
            1. Ingestion &amp; Dataset
          </div>

          <div className="space-y-3">
            <div className="bg-slate-950/60 p-2.5 rounded border border-slate-800/80">
              <div className="text-[11px] text-slate-400">Current Ingestion Source:</div>
              <div className="font-mono text-slate-200 text-xs font-semibold truncate mt-0.5">
                {dataSourceName}
              </div>
            </div>

            <div className="space-y-1.5">
              <input
                ref={fileInputRef}
                type="file"
                accept=".csv"
                onChange={handleFileChange}
                className="hidden"
              />
              <button
                onClick={() => fileInputRef.current?.click()}
                className="w-full py-1.5 px-3 rounded bg-slate-800 hover:bg-slate-700/80 text-slate-200 border border-slate-700 flex items-center justify-center gap-2 transition-colors text-xs cursor-pointer"
              >
                <Upload className="w-3.5 h-3.5 text-slate-400" />
                Upload Custom CSV (CIC-IDS2017)
              </button>

              {onDownloadSampleCSV && (
                <button
                  onClick={onDownloadSampleCSV}
                  className="w-full py-1.5 px-3 rounded bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 flex items-center justify-center gap-2 transition-colors text-[11px] cursor-pointer"
                >
                  <Download className="w-3 h-3 text-blue-400" />
                  Download Sample CSV (1,000 Flows)
                </button>
              )}
            </div>

            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>Synthetic Sample Size</span>
                <span className="font-mono font-semibold text-blue-400">{hyperparams.datasetSize}</span>
              </div>
              <input
                type="range"
                min="1000"
                max="6000"
                step="500"
                value={hyperparams.datasetSize}
                onChange={(e) => onChangeHyperparams({ datasetSize: Number(e.target.value) })}
                className="w-full accent-blue-500 bg-slate-800 rounded h-1.5 cursor-pointer"
              />
              <div className="flex justify-between text-[10px] text-slate-400">
                <span>1,000</span>
                <span>6,000</span>
              </div>
            </div>

            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>Random Seed</span>
                <span className="font-mono font-semibold text-slate-300">{hyperparams.randomSeed}</span>
              </div>
              <input
                type="number"
                min="1"
                max="9999"
                value={hyperparams.randomSeed}
                onChange={(e) => onChangeHyperparams({ randomSeed: Number(e.target.value) || 42 })}
                className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-200 font-mono text-xs focus:border-blue-500 focus:outline-none"
              />
            </div>

            <button
              onClick={onRegenerateData}
              className="w-full py-1.5 px-3 rounded bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/40 flex items-center justify-center gap-2 transition-colors text-xs font-medium"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Re-generate Dataset
            </button>
          </div>
        </div>

        {/* 2. Model Hyperparameters & Decision Fusion */}
        <div className="pt-2 border-t border-slate-800">
          <div className="flex items-center gap-1.5 font-semibold text-slate-200 uppercase tracking-wider text-[11px] mb-3">
            <Sliders className="w-3.5 h-3.5 text-amber-400" />
            2. ML & Sensitivity Controls
          </div>

          <div className="space-y-4">
            {/* Isolation Forest Contamination */}
            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>IF Contamination (Sensitivity)</span>
                <span className="font-mono font-semibold text-amber-400">
                  {(hyperparams.ifContamination * 100).toFixed(0)}%
                </span>
              </div>
              <input
                type="range"
                min="0.01"
                max="0.25"
                step="0.01"
                value={hyperparams.ifContamination}
                onChange={(e) => onChangeHyperparams({ ifContamination: parseFloat(e.target.value) })}
                className="w-full accent-amber-500 bg-slate-800 rounded h-1.5 cursor-pointer"
              />
              <p className="text-[10px] text-slate-400 mt-1">
                Proportion of anomalies in baseline traffic. Higher catches more zero-days.
              </p>
            </div>

            {/* RF Confidence Threshold */}
            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>RF Attack Confidence Threshold</span>
                <span className="font-mono font-semibold text-emerald-400">
                  {(hyperparams.rfConfidenceThreshold * 100).toFixed(0)}%
                </span>
              </div>
              <input
                type="range"
                min="0.50"
                max="0.95"
                step="0.05"
                value={hyperparams.rfConfidenceThreshold}
                onChange={(e) => onChangeHyperparams({ rfConfidenceThreshold: parseFloat(e.target.value) })}
                className="w-full accent-emerald-500 bg-slate-800 rounded h-1.5 cursor-pointer"
              />
              <p className="text-[10px] text-slate-400 mt-1">
                Cutoff to confirm known attack signatures before checking outlier engine.
              </p>
            </div>

            {/* Random Forest Trees */}
            <div>
              <label className="block text-slate-300 mb-1">Random Forest Trees (n_estimators)</label>
              <div className="grid grid-cols-3 gap-1.5">
                {[50, 100, 150].map((trees) => (
                  <button
                    key={trees}
                    onClick={() => onChangeHyperparams({ rfTrees: trees })}
                    className={`py-1 rounded text-xs font-mono font-medium transition-colors border ${
                      hyperparams.rfTrees === trees
                        ? 'bg-blue-600 text-white border-blue-500'
                        : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    {trees}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* System Architecture Tag */}
        <div className="pt-2 border-t border-slate-800">
          <div className="flex items-center gap-1.5 font-semibold text-slate-200 uppercase tracking-wider text-[11px] mb-2">
            <Cpu className="w-3.5 h-3.5 text-indigo-400" />
            Dual-Engine Pipeline
          </div>
          <div className="space-y-1.5 text-[11px] text-slate-400">
            <div className="flex items-center justify-between">
              <span>Supervised:</span>
              <span className="text-slate-200 font-medium">Random Forest</span>
            </div>
            <div className="flex items-center justify-between">
              <span>Unsupervised:</span>
              <span className="text-slate-200 font-medium">Isolation Forest</span>
            </div>
            <div className="flex items-center justify-between">
              <span>Decision:</span>
              <span className="text-blue-400 font-medium">Hierarchical Fusion</span>
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
};
