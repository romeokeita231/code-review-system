export {
  pair,
  mergedIdOf,
  lineUnionSize,
  intersectionSize,
  type GtSpan,
  type Interval,
} from "./pairing.js";
export {
  rowMetrics,
  aggregate,
  sourceErrorRates,
  unknownCoverage,
  type AggregateMetrics,
  type RowInput,
  type RowMetrics,
  type SourceErrorStat,
  type UnknownCoverage,
} from "./metrics.js";
export {
  LADDER,
  loadDataset,
  runBaseline,
  runReplay,
  effectiveConfig,
  effectiveConfigHash,
  changeEventOf,
  sourceNamesFor,
  persistRunRecords,
  type DatasetSample,
  type LabelSpan,
  type LoadedDataset,
  type PersistedRunFile,
  type ReplayResult,
  type RunBaselineOptions,
  type RunReplayOptions,
} from "./replay.js";
export {
  RecordedSource,
  missingRecording,
  loadRecorded,
  type RecordedBySample,
} from "./recorded.js";
export { writeJsonl, readJsonl, appendRow, encodeRow } from "./jsonl.js";
