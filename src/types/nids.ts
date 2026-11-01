export type FlowClass = 'BENIGN' | 'DDoS' | 'PortScan' | 'Unseen_Attack';

export type HybridDecision = 'Normal' | 'Known Attack' | 'Potential Unknown/Anomalous Attack';

export interface NetworkFlow {
  id: string;
  flow_duration_ms: number;
  total_fwd_packets: number;
  total_bwd_packets: number;
  fwd_pkt_len_mean: number;
  bwd_pkt_len_mean: number;
  flow_bytes_per_sec: number;
  flow_pkts_per_sec: number;
  fwd_iat_mean: number;
  bwd_iat_mean: number;
  syn_flag_count: number;
  ack_flag_count: number;
  avg_packet_size: number;
  true_label: FlowClass;
  timestamp?: number;
}

export interface EvaluatedFlow extends NetworkFlow {
  rf_predicted: 'BENIGN' | 'DDoS' | 'PortScan';
  rf_confidence: number;
  if_score: number; // Decision function: < 0 is anomaly
  if_anomaly: boolean;
  hybrid_decision: HybridDecision;
  fusion_reason: string;
  pca_x?: number;
  pca_y?: number;
}

export interface ModelMetrics {
  totalFlows: number;
  knownAttacks: number;
  anomaliesFlagged: number;
  normalFlows: number;
  zeroDayTotal: number;
  zeroDayCaught: number;
  zeroDayCaptureRate: number;
  benignFalseAlarmRate: number;
  overallAccuracy: number;
  confusionMatrix: {
    labels: string[];
    matrix: number[][]; // [groundTruth][predicted]
  };
  featureImportances: { feature: string; importance: number; label: string }[];
}

export interface ModelHyperparams {
  ifContamination: number;
  rfConfidenceThreshold: number;
  rfTrees: number;
  datasetSize: number;
  randomSeed: number;
}
