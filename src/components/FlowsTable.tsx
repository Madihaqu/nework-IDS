import React, { useState, useMemo } from 'react';
import { EvaluatedFlow, HybridDecision } from '../types/nids';
import { Download, Search, Filter, ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react';

interface FlowsTableProps {
  flows: EvaluatedFlow[];
}

export const FlowsTable: React.FC<FlowsTableProps> = ({ flows }) => {
  const [filterType, setFilterType] = useState<string>('Malicious & Anomalies Only');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [currentPage, setCurrentPage] = useState<number>(1);
  const pageSize = 15;

  const filteredFlows = useMemo(() => {
    return flows.filter((flow) => {
      // 1. Category Filter
      if (filterType === 'Malicious & Anomalies Only') {
        if (flow.hybrid_decision === 'Normal') return false;
      } else if (filterType === 'Known Attacks Only') {
        if (flow.hybrid_decision !== 'Known Attack') return false;
      } else if (filterType === 'Potential Unknown/Anomalous Only') {
        if (flow.hybrid_decision !== 'Potential Unknown/Anomalous Attack') return false;
      }

      // 2. Search Query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesId = flow.id.toLowerCase().includes(q);
        const matchesReason = flow.fusion_reason.toLowerCase().includes(q);
        const matchesTruth = flow.true_label.toLowerCase().includes(q);
        const matchesDecision = flow.hybrid_decision.toLowerCase().includes(q);
        if (!matchesId && !matchesReason && !matchesTruth && !matchesDecision) {
          return false;
        }
      }

      return true;
    });
  }, [flows, filterType, searchQuery]);

  const totalPages = Math.ceil(filteredFlows.length / pageSize) || 1;
  const paginatedFlows = filteredFlows.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const handleExportCSV = () => {
    const headers = [
      'Flow_ID',
      'Hybrid_Decision',
      'Fusion_Reason',
      'RF_Predicted',
      'RF_Confidence',
      'IF_Anomaly_Score',
      'Ground_Truth',
      'Flow_Duration_ms',
      'Flow_Packets_per_sec',
      'Flow_Bytes_per_sec',
      'Avg_Packet_Size',
      'SYN_Flag',
      'ACK_Flag'
    ];

    const rows = filteredFlows.map((f) => [
      f.id,
      f.hybrid_decision,
      `"${f.fusion_reason.replace(/"/g, '""')}"`,
      f.rf_predicted,
      (f.rf_confidence * 100).toFixed(1) + '%',
      f.if_score.toFixed(4),
      f.true_label,
      f.flow_duration_ms.toFixed(1),
      f.flow_pkts_per_sec.toFixed(1),
      f.flow_bytes_per_sec.toFixed(1),
      f.avg_packet_size.toFixed(1),
      f.syn_flag_count,
      f.ack_flag_count
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `hybrid_nids_incidents_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const getDecisionBadge = (decision: HybridDecision) => {
    switch (decision) {
      case 'Normal':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <ShieldCheck className="w-3 h-3" /> Normal
          </span>
        );
      case 'Known Attack':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <ShieldAlert className="w-3 h-3" /> Known Attack
          </span>
        );
      case 'Potential Unknown/Anomalous Attack':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3 h-3" /> Unknown Anomaly
          </span>
        );
    }
  };

  return (
    <div className="space-y-4">
      {/* Controls Bar */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 p-4 rounded-xl bg-slate-900/90 border border-slate-800">
        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <span className="text-slate-400 font-semibold mr-1 flex items-center gap-1">
            <Filter className="w-3.5 h-3.5" /> Filter:
          </span>
          {[
            'Malicious & Anomalies Only',
            'Known Attacks Only',
            'Potential Unknown/Anomalous Only',
            'All Traffic',
          ].map((type) => (
            <button
              key={type}
              onClick={() => {
                setFilterType(type);
                setCurrentPage(1);
              }}
              className={`px-2.5 py-1 rounded text-xs transition-colors border ${
                filterType === type
                  ? 'bg-blue-600 text-white border-blue-500 font-medium'
                  : 'bg-slate-950 text-slate-300 border-slate-800 hover:border-slate-700'
              }`}
            >
              {type}
            </button>
          ))}
        </div>

        {/* Search & Export */}
        <div className="flex items-center gap-2">
          <div className="relative flex-1 sm:w-64">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search flows, reasons, IDs..."
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full bg-slate-950 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <button
            onClick={handleExportCSV}
            className="py-1.5 px-3 rounded bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/40 flex items-center gap-1.5 text-xs font-medium shrink-0 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Export CSV ({filteredFlows.length})
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="rounded-xl bg-slate-900/90 border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left border-collapse">
            <thead>
              <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[10px]">
                <th className="py-3 px-3.5">Flow ID</th>
                <th className="py-3 px-3">Hybrid Decision</th>
                <th className="py-3 px-3">Decision Logic & Reasoning</th>
                <th className="py-3 px-3">RF Model</th>
                <th className="py-3 px-3">RF Conf.</th>
                <th className="py-3 px-3">IF Anomaly Score</th>
                <th className="py-3 px-3">Ground Truth</th>
                <th className="py-3 px-3 text-right">Packets/s</th>
                <th className="py-3 px-3 text-right">Avg Size</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {paginatedFlows.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-500 font-sans">
                    No matching network flows found for the selected filter.
                  </td>
                </tr>
              ) : (
                paginatedFlows.map((flow) => (
                  <tr key={flow.id} className="hover:bg-slate-800/40 transition-colors font-sans">
                    <td className="py-2.5 px-3.5 font-mono text-slate-300 font-semibold text-[11px]">
                      {flow.id}
                    </td>
                    <td className="py-2.5 px-3">
                      {getDecisionBadge(flow.hybrid_decision)}
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 text-[11px]">
                      {flow.fusion_reason}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-slate-300">
                      {flow.rf_predicted}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-slate-300">
                      {(flow.rf_confidence * 100).toFixed(1)}%
                    </td>
                    <td className={`py-2.5 px-3 font-mono text-[11px] font-semibold ${
                      flow.if_score < 0 ? 'text-amber-400' : 'text-slate-400'
                    }`}>
                      {flow.if_score.toFixed(3)}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`text-[11px] font-mono px-1.5 py-0.5 rounded ${
                        flow.true_label === 'BENIGN'
                          ? 'text-emerald-400 bg-emerald-500/10'
                          : flow.true_label === 'Unseen_Attack'
                          ? 'text-amber-400 bg-amber-500/10 font-bold'
                          : 'text-rose-400 bg-rose-500/10'
                      }`}>
                        {flow.true_label}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono text-slate-300 text-[11px]">
                      {flow.flow_pkts_per_sec.toFixed(1)}
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono text-slate-300 text-[11px]">
                      {flow.avg_packet_size.toFixed(1)} B
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className="p-3 bg-slate-950/60 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <div>
            Showing {filteredFlows.length === 0 ? 0 : (currentPage - 1) * pageSize + 1} to{' '}
            {Math.min(currentPage * pageSize, filteredFlows.length)} of {filteredFlows.length} flows
          </div>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 hover:border-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Previous
            </button>
            <span className="px-2 font-mono text-slate-300">
              {currentPage} / {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 hover:border-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
