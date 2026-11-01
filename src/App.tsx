import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { NetworkFlow, ModelHyperparams, TimelinePoint } from './types/nids';
import { generateSyntheticFlows, parseCSVToFlows, exportFlowsToCSV } from './lib/syntheticData';
import { runHybridPipeline } from './lib/mlEngine';
import { Sidebar } from './components/Sidebar';
import { MetricsCards } from './components/MetricsCards';
import { DetectionAnalytics } from './components/DetectionAnalytics';
import { FlowsTable } from './components/FlowsTable';
import { LiveInspector } from './components/LiveInspector';
import { PythonScriptViewer } from './components/PythonScriptViewer';
import { DeploymentGuide } from './components/DeploymentGuide';
import {
  BarChart2,
  Table as TableIcon,
  Zap,
  Code,
  Shield,
  Radio,
  ExternalLink,
  Cpu,
  Rocket
} from 'lucide-react';

export default function App() {
  const [hyperparams, setHyperparams] = useState<ModelHyperparams>({
    ifContamination: 0.08,
    rfConfidenceThreshold: 0.70,
    rfTrees: 100,
    datasetSize: 3000,
    randomSeed: 42,
    streamRate: 10, // 10 flows/sec default
  });

  const [dataSourceName, setDataSourceName] = useState<string>(
    'Synthetic CIC-IDS2017 (Default Fallback)'
  );

  const [activeTab, setActiveTab] = useState<'analytics' | 'table' | 'inspector' | 'code' | 'deploy'>(
    'analytics'
  );

  const [rawDataset, setRawDataset] = useState<NetworkFlow[]>(() =>
    generateSyntheticFlows(3000, 42)
  );

  const [isStreaming, setIsStreaming] = useState<boolean>(false);

  // Rolling real-time traffic timeline for chart (last 16 points)
  const [timeline, setTimeline] = useState<TimelinePoint[]>(() => {
    const pts: TimelinePoint[] = [];
    const now = Date.now();
    for (let i = 15; i >= 0; i--) {
      pts.push({
        timeLabel: `${i}s ago`,
        timestamp: now - i * 1000,
        normalCount: Math.round(18 + Math.random() * 8),
        knownCount: Math.random() > 0.65 ? Math.round(2 + Math.random() * 5) : 0,
        anomalyCount: Math.random() > 0.75 ? Math.round(1 + Math.random() * 3) : 0,
        totalPackets: Math.round(120 + Math.random() * 80),
        flowRate: Math.round(12 + Math.random() * 6),
      });
    }
    return pts;
  });

  // Compute Hybrid ML evaluations
  const { evaluatedFlows, metrics } = useMemo(() => {
    return runHybridPipeline(rawDataset, hyperparams);
  }, [rawDataset, hyperparams]);

  // Handle hyperparam update
  const handleUpdateHyperparams = useCallback((params: Partial<ModelHyperparams>) => {
    setHyperparams((prev) => ({ ...prev, ...params }));
  }, []);

  // Handle data regeneration
  const handleRegenerateData = useCallback(() => {
    const fresh = generateSyntheticFlows(hyperparams.datasetSize, hyperparams.randomSeed + Math.floor(Math.random() * 100));
    setRawDataset(fresh);
    setDataSourceName(`Synthetic CIC-IDS2017 (Generated ${hyperparams.datasetSize} flows)`);
  }, [hyperparams.datasetSize, hyperparams.randomSeed]);

  // Handle custom CSV upload
  const handleFileUpload = useCallback((file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      if (text) {
        const parsed = parseCSVToFlows(text);
        if (parsed.length > 0) {
          setRawDataset(parsed);
          setDataSourceName(`Uploaded CSV: ${file.name} (${parsed.length} rows)`);
        } else {
          alert('Could not parse valid network flows from this CSV. Using synthetic dataset.');
        }
      }
    };
    reader.readAsText(file);
  }, []);

  // Download Sample CSV for testing client-side file upload
  const handleDownloadSampleCSV = useCallback(() => {
    const sampleFlows = generateSyntheticFlows(1000, 99);
    const csvContent = exportFlowsToCSV(sampleFlows);
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', 'cicids2017_sample_1000.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }, []);

  // Live packet streaming simulation (10-20 flows/sec)
  useEffect(() => {
    if (!isStreaming) return;

    const rate = hyperparams.streamRate || 10;
    // Interval runs every 500ms; batches of (rate / 2) flows per tick
    const batchSize = Math.max(1, Math.round(rate / 2));

    const interval = setInterval(() => {
      const newBatch: NetworkFlow[] = [];
      let batchNormals = 0;
      let batchKnown = 0;
      let batchAnomaly = 0;

      for (let k = 0; k < batchSize; k++) {
        const dice = Math.random();
        let flowType: 'BENIGN' | 'DDoS' | 'PortScan' | 'Unseen_Attack' = 'BENIGN';
        if (dice > 0.85) {
          flowType = 'DDoS';
          batchKnown++;
        } else if (dice > 0.73) {
          flowType = 'PortScan';
          batchKnown++;
        } else if (dice > 0.65) {
          flowType = 'Unseen_Attack';
          batchAnomaly++;
        } else {
          batchNormals++;
        }

        const generated = generateSyntheticFlows(12, Math.floor(Math.random() * 100000)).find(
          (f) => f.true_label === flowType
        );

        if (generated) {
          generated.id = `LIVE-${Date.now().toString().slice(-4)}-${k}`;
          newBatch.push(generated);
        }
      }

      if (newBatch.length > 0) {
        setRawDataset((prev) => [...newBatch, ...prev.slice(0, 4999 - newBatch.length)]);
      }

      // Update rolling timeline
      setTimeline((prev) => {
        const next = [...prev.slice(1)];
        const lastRate = batchSize * 2;
        next.push({
          timeLabel: 'Just now',
          timestamp: Date.now(),
          normalCount: batchNormals,
          knownCount: batchKnown,
          anomalyCount: batchAnomaly,
          totalPackets: batchNormals * 15 + batchKnown * 350 + batchAnomaly * 60,
          flowRate: lastRate,
        });
        return next;
      });
    }, 500);

    return () => clearInterval(interval);
  }, [isStreaming, hyperparams.streamRate]);

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden font-sans">
      {/* Sidebar Navigation & Controls */}
      <Sidebar
        hyperparams={hyperparams}
        onChangeHyperparams={handleUpdateHyperparams}
        onRegenerateData={handleRegenerateData}
        onFileUpload={handleFileUpload}
        onDownloadSampleCSV={handleDownloadSampleCSV}
        dataSourceName={dataSourceName}
        isStreaming={isStreaming}
        onToggleStreaming={() => setIsStreaming(!isStreaming)}
        streamRate={hyperparams.streamRate || 10}
      />

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col h-full overflow-hidden bg-slate-950">
        {/* Top Navbar */}
        <header className="h-16 px-6 border-b border-slate-800 bg-slate-900/60 backdrop-blur flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-600/10 border border-blue-500/30 text-blue-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="font-bold text-sm text-slate-100">
                  Hybrid Network Intrusion Detection System
                </h2>
                <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/30 font-mono">
                  CSE CAPSTONE
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Random Forest (Known Attacks) + Isolation Forest (Zero-Day Anomaly Detection) + Decision Fusion
              </p>
            </div>
          </div>

          {/* Quick tab switcher */}
          <div className="flex items-center gap-1.5 p-1 rounded-lg bg-slate-950 border border-slate-800 text-xs">
            <button
              onClick={() => setActiveTab('analytics')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded font-medium transition-colors ${
                activeTab === 'analytics'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <BarChart2 className="w-3.5 h-3.5" />
              Detection Analytics
            </button>

            <button
              onClick={() => setActiveTab('table')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded font-medium transition-colors ${
                activeTab === 'table'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <TableIcon className="w-3.5 h-3.5" />
              Flagged Flows
              {metrics.knownAttacks + metrics.anomaliesFlagged > 0 && (
                <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] bg-rose-500 text-white font-mono">
                  {metrics.knownAttacks + metrics.anomaliesFlagged}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('inspector')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded font-medium transition-colors ${
                activeTab === 'inspector'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Zap className="w-3.5 h-3.5" />
              Live Flow Inspector
            </button>

            <button
              onClick={() => setActiveTab('code')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded font-medium transition-colors ${
                activeTab === 'code'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Code className="w-3.5 h-3.5" />
              Python (app.py)
            </button>

            <button
              onClick={() => setActiveTab('deploy')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded font-medium transition-colors ${
                activeTab === 'deploy'
                  ? 'bg-emerald-600 text-white shadow-sm'
                  : 'text-emerald-400 hover:text-emerald-300'
              }`}
            >
              <Rocket className="w-3.5 h-3.5" />
              Static Deploy (Vercel / GitHub)
            </button>
          </div>
        </header>

        {/* Scrollable Dashboard Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Top 5 KPI Metrics Cards */}
          <MetricsCards metrics={metrics} isStreaming={isStreaming} />

          {/* Active Tab View */}
          {activeTab === 'analytics' && (
            <DetectionAnalytics
              evaluatedFlows={evaluatedFlows}
              metrics={metrics}
              timeline={timeline}
              isStreaming={isStreaming}
            />
          )}

          {activeTab === 'table' && (
            <FlowsTable flows={evaluatedFlows} />
          )}

          {activeTab === 'inspector' && (
            <LiveInspector hyperparams={hyperparams} />
          )}

          {activeTab === 'code' && (
            <PythonScriptViewer />
          )}

          {activeTab === 'deploy' && (
            <DeploymentGuide />
          )}
        </div>
      </main>
    </div>
  );
}
