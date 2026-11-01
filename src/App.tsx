import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { NetworkFlow, ModelHyperparams } from './types/nids';
import { generateSyntheticFlows, parseCSVToFlows } from './lib/syntheticData';
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

  // Live packet streaming simulation
  useEffect(() => {
    if (!isStreaming) return;

    const interval = setInterval(() => {
      // Generate 1 new flow with varying probabilities
      const dice = Math.random();
      let flowType: 'BENIGN' | 'DDoS' | 'PortScan' | 'Unseen_Attack' = 'BENIGN';
      if (dice > 0.88) flowType = 'DDoS';
      else if (dice > 0.76) flowType = 'PortScan';
      else if (dice > 0.70) flowType = 'Unseen_Attack';

      const singleFlow = generateSyntheticFlows(20, Math.floor(Math.random() * 10000)).find(
        (f) => f.true_label === flowType
      );

      if (singleFlow) {
        singleFlow.id = `LIVE-${Date.now().toString().slice(-4)}`;
        setRawDataset((prev) => [singleFlow, ...prev.slice(0, 3999)]);
      }
    }, 750);

    return () => clearInterval(interval);
  }, [isStreaming]);

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden font-sans">
      {/* Sidebar Navigation & Controls */}
      <Sidebar
        hyperparams={hyperparams}
        onChangeHyperparams={handleUpdateHyperparams}
        onRegenerateData={handleRegenerateData}
        onFileUpload={handleFileUpload}
        dataSourceName={dataSourceName}
        isStreaming={isStreaming}
        onToggleStreaming={() => setIsStreaming(!isStreaming)}
        streamRate={1.3}
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
          {/* Top 4 Metrics Cards */}
          <MetricsCards metrics={metrics} />

          {/* Active Tab View */}
          {activeTab === 'analytics' && (
            <DetectionAnalytics evaluatedFlows={evaluatedFlows} metrics={metrics} />
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
