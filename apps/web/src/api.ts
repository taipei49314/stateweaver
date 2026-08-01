export type Endpoint =
  '/healthz' | '/v1/demo/overview' | '/v1/demo/worlds' | '/v1/demo/twin' | '/v1/demo/replay';

export type Provenance = {
  boundary_label: 'SYNTHETIC LOCAL LAB';
  run_id: 'sw_demo_01';
  commit_placeholder: string;
  mode: 'deterministic';
  oracle: 'deterministic';
  model_calls: 0;
  workspace: 'local-lab';
  certification: 'not release-certified';
  fixture_status: 'saved synthetic implementation evidence';
  proof_status: 'not materialized proof';
};

export type RunHashes = {
  root_hash: string;
  plan_hash: string;
  oracle_hash: string;
  evidence_hash: string;
};

export type TierCounts = {
  root: 1;
  ghost: 24;
  replay: 4;
  simulated: 2;
  materialized: 1;
  pruned: 17;
  flow: '24 → 4 → 2 → 1';
};

export type Stage = {
  sequence: 1 | 2 | 3 | 4 | 5 | 6;
  label:
    | 'Root captured'
    | 'World search'
    | 'Chain compiled'
    | 'Clean replay'
    | 'Patched comparison'
    | 'Fixture integrity checked';
  status: 'READY' | 'BLOCKED_BY_FIX';
  evidence_digest: string;
};

export type RequiredFragment = {
  fragment_id: 'fragment-a' | 'fragment-b' | 'fragment-c';
  label: 'Fragment A' | 'Fragment B' | 'Fragment C';
  semantic_label:
    | 'historic session retained'
    | 'async policy propagation delayed'
    | 'stale authorization decision observed';
  evidence_digest: string;
};

export type Verdict = {
  lane: 'Vulnerable' | 'Patched' | 'Control A' | 'Control B';
  verdict: 'VIOLATED' | 'BLOCKED_BY_FIX' | 'SATISFIED';
  color: 'violation' | 'blocked' | 'satisfied';
  evidence_digest: string;
};

export type Marker = {
  ordinal: 1 | 2 | 3 | 4 | 5;
  signature: string;
  status: 'matching fixture';
};

export type Overview = {
  provenance: Provenance;
  hashes: RunHashes;
  title: 'Deterministic state exploration';
  stages: Stage[];
  tier_counts: TierCounts;
  required_fragments: RequiredFragment[];
  run_markers: Marker[];
  verdicts: Verdict[];
};

export type WorldNode = {
  node_id: string;
  tier: 'ROOT' | 'GHOST' | 'REPLAY' | 'SIMULATED' | 'MATERIALIZED';
  fingerprint: string;
  pruned: boolean;
  status: 'ACTIVE' | 'PRUNED' | 'RECORDED';
};

export type WorldEdge = {
  from_node_id: string;
  to_node_id: string;
  relation: 'explores' | 'replays' | 'simulates' | 'materializes';
  pruned: boolean;
};

export type Worlds = {
  provenance: Provenance;
  hashes: RunHashes;
  tier_counts: TierCounts;
  nodes: WorldNode[];
  edges: WorldEdge[];
  selected_inspector: {
    node_id: 'materialized-01';
    fingerprint: string;
    tier: 'MATERIALIZED';
    parent_node_ids: ['simulated-01', 'simulated-02'];
    status: 'SELECTED';
  };
};

export type Fact = {
  label: 'precondition' | 'typed action' | 'effect' | 'evidence';
  summary: string;
  digest: string;
};

export type TwinFragment = {
  fragment_id: 'fragment-a' | 'fragment-b' | 'fragment-c';
  label: 'Fragment A' | 'Fragment B' | 'Fragment C';
  semantic_label: RequiredFragment['semantic_label'];
  provenance: {
    observation_status: 'SYNTHETIC';
    source_node_id: 'replay-01' | 'replay-02' | 'replay-03';
    source_fingerprint: string;
  };
  precondition: Fact;
  typed_action: Fact;
  effect: Fact;
  evidence: Fact;
  fidelity: {
    completeness: 'fixture-only';
    ordering: 'deterministic fixture';
    timing: 'not modeled';
    determinism: 'deterministic';
  };
  state_delta: Array<{ field: string; before: string; after: string; effect: string }>;
  runtime_trace: {
    trace_id: 'trace-local-fragment-a' | 'trace-local-fragment-b' | 'trace-local-fragment-c';
    trace_digest: string;
    runtime: 'local synthetic runtime';
  };
  oracle_binding: { oracle: 'deterministic'; binding_digest: string; oracle_hash: string };
};

export type Twin = {
  provenance: Provenance;
  hashes: RunHashes;
  title: 'Security Semantic Twin';
  fragments: TwinFragment[];
  selected_fragment_id: 'fragment-c';
};

export type ReplayStep = {
  sequence: 1 | 2 | 3;
  label: 'Session state retained' | 'Policy state compared' | 'Decision outcome recorded';
  evidence_digest: string;
  verdict: 'SATISFIED' | 'VIOLATED' | 'BLOCKED_BY_FIX';
};

export type ReplayLane = {
  lane: 'Vulnerable' | 'Patched';
  plan_hash: string;
  steps: ReplayStep[];
  terminal_verdict: 'VIOLATED' | 'BLOCKED_BY_FIX';
};

export type Replay = {
  provenance: Provenance;
  hashes: RunHashes;
  title: 'Clean-root replay';
  vulnerable: ReplayLane;
  patched: ReplayLane;
  controls: Array<{
    control_id: 'control-a' | 'control-b';
    label: 'Control A' | 'Control B';
    verdict: 'SATISFIED';
    color: 'satisfied';
    evidence_digest: string;
  }>;
  selected_observation: {
    label: 'Observation (redacted)';
    summary: 'synthetic-local decision observation [redacted]';
    digest: string;
  };
  evidence_manifest: Array<{
    entry_id: 'evidence-01' | 'evidence-02' | 'evidence-03' | 'evidence-04' | 'evidence-05';
    label:
      | 'Recorded event summary'
      | 'Typed state delta'
      | 'Oracle comparison'
      | 'Policy snapshot'
      | 'Replay signature';
    digest: string;
    verification: 'digest-only fixture';
  }>;
  run_markers: Marker[];
};

type Health = { status: 'ok'; mode: 'read-only'; provenance: Provenance };

function ensure(condition: unknown, message: string): asserts condition {
  if (!condition) throw Error(message);
}

const o = (value: unknown): Record<string, unknown> => {
  ensure(typeof value === 'object' && value !== null && !Array.isArray(value), 'Invalid fixture');
  return value as Record<string, unknown>;
};

const a = (value: unknown): unknown[] => {
  ensure(Array.isArray(value), 'Invalid fixture');
  return value;
};

const s = (value: unknown): string => {
  ensure(typeof value === 'string', 'Invalid fixture string');
  return value;
};

const b = (value: unknown): boolean => {
  ensure(typeof value === 'boolean', 'Invalid fixture boolean');
  return value;
};

const n = (value: unknown): number => {
  ensure(typeof value === 'number' && Number.isInteger(value), 'Invalid fixture integer');
  return value;
};

const d = (value: unknown): string => {
  const digest = s(value);
  ensure(/^[a-f0-9]{64}$/.test(digest), 'Invalid digest');
  return digest;
};

const commit = (value: unknown): string => {
  const placeholder = s(value);
  ensure(/^[a-f0-9]{40}$/.test(placeholder), 'Invalid commit placeholder');
  return placeholder;
};

const one = <T extends string>(value: unknown, allowed: readonly T[]): T => {
  const candidate = s(value) as T;
  ensure(allowed.includes(candidate), 'Invalid enum');
  return candidate;
};

const len = (value: unknown, length: number): unknown[] => {
  const values = a(value);
  ensure(values.length === length, 'Invalid fixture count');
  return values;
};

const same = (left: unknown, right: unknown): boolean =>
  JSON.stringify(left) === JSON.stringify(right);

const canonicalValue = (value: unknown): unknown => {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === 'object') {
    const source = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(source)
        .sort()
        .map((key) => [key, canonicalValue(source[key])]),
    );
  }
  return value;
};

export const canonicalJson = (value: unknown): string => JSON.stringify(canonicalValue(value));

export async function canonicalSha256(value: unknown): Promise<string> {
  ensure(globalThis.crypto?.subtle, 'Web Crypto is required for fixture integrity checks');
  const bytes = await globalThis.crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(canonicalJson(value)),
  );
  return [...new Uint8Array(bytes)].map((item) => item.toString(16).padStart(2, '0')).join('');
}

async function digestMatches(actual: string, value: unknown, message: string): Promise<void> {
  ensure(actual === (await canonicalSha256(value)), message);
}

const prov = (value: unknown): Provenance => {
  const x = o(value);
  ensure(x.model_calls === 0, 'Invalid model calls');
  return {
    boundary_label: one(x.boundary_label, ['SYNTHETIC LOCAL LAB']),
    run_id: one(x.run_id, ['sw_demo_01']),
    commit_placeholder: commit(x.commit_placeholder),
    mode: one(x.mode, ['deterministic']),
    oracle: one(x.oracle, ['deterministic']),
    model_calls: 0,
    workspace: one(x.workspace, ['local-lab']),
    certification: one(x.certification, ['not release-certified']),
    fixture_status: one(x.fixture_status, ['saved synthetic implementation evidence']),
    proof_status: one(x.proof_status, ['not materialized proof']),
  };
};

const hashes = (value: unknown): RunHashes => {
  const x = o(value);
  const result = {
    root_hash: d(x.root_hash),
    plan_hash: d(x.plan_hash),
    oracle_hash: d(x.oracle_hash),
    evidence_hash: d(x.evidence_hash),
  };
  ensure(new Set(Object.values(result)).size === 4, 'Run hashes must be distinct');
  return result;
};

const tiers = (value: unknown): TierCounts => {
  const x = o(value);
  ensure(
    x.root === 1 &&
      x.ghost === 24 &&
      x.replay === 4 &&
      x.simulated === 2 &&
      x.materialized === 1 &&
      x.pruned === 17,
    'Invalid tiers',
  );
  return {
    root: 1,
    ghost: 24,
    replay: 4,
    simulated: 2,
    materialized: 1,
    pruned: 17,
    flow: one(x.flow, ['24 → 4 → 2 → 1']),
  };
};

const markers = (value: unknown): Marker[] => {
  const result = len(value, 5).map((item) => {
    const x = o(item);
    const ordinal = n(x.ordinal);
    ensure([1, 2, 3, 4, 5].includes(ordinal), 'Invalid run ordinal');
    return {
      ordinal: ordinal as Marker['ordinal'],
      signature: d(x.signature),
      status: one(x.status, ['matching fixture']),
    };
  });
  ensure(
    same(
      result.map((item) => item.ordinal),
      [1, 2, 3, 4, 5],
    ) && new Set(result.map((item) => item.signature)).size === 1,
    'Run markers are not a closed five-run match',
  );
  return result;
};

const parseOverview = (x: Record<string, unknown>, p: Provenance, h: RunHashes): Overview => {
  const stageLabels: Stage['label'][] = [
    'Root captured',
    'World search',
    'Chain compiled',
    'Clean replay',
    'Patched comparison',
    'Fixture integrity checked',
  ];
  const stages = len(x.stages, 6).map((item, index) => {
    const q = o(item);
    const sequence = n(q.sequence);
    ensure(sequence === index + 1, 'Stages are not ordered');
    const result: Stage = {
      sequence: sequence as Stage['sequence'],
      label: one(q.label, stageLabels),
      status: one(q.status, ['READY', 'BLOCKED_BY_FIX']),
      evidence_digest: d(q.evidence_digest),
    };
    ensure(result.label === stageLabels[index], 'Stage label mismatch');
    ensure(result.status === (index === 4 ? 'BLOCKED_BY_FIX' : 'READY'), 'Stage status mismatch');
    return result;
  });
  const fragmentSpecs = [
    ['fragment-a', 'Fragment A', 'historic session retained'],
    ['fragment-b', 'Fragment B', 'async policy propagation delayed'],
    ['fragment-c', 'Fragment C', 'stale authorization decision observed'],
  ] as const;
  const required_fragments = len(x.required_fragments, 3).map((item, index) => {
    const q = o(item);
    const spec = fragmentSpecs[index];
    const result: RequiredFragment = {
      fragment_id: one(q.fragment_id, ['fragment-a', 'fragment-b', 'fragment-c']),
      label: one(q.label, ['Fragment A', 'Fragment B', 'Fragment C']),
      semantic_label: one(q.semantic_label, [
        'historic session retained',
        'async policy propagation delayed',
        'stale authorization decision observed',
      ]),
      evidence_digest: d(q.evidence_digest),
    };
    ensure(
      same([result.fragment_id, result.label, result.semantic_label], spec),
      'Required fragment mismatch',
    );
    return result;
  });
  const verdictSpecs = [
    ['Vulnerable', 'VIOLATED', 'violation'],
    ['Patched', 'BLOCKED_BY_FIX', 'blocked'],
    ['Control A', 'SATISFIED', 'satisfied'],
    ['Control B', 'SATISFIED', 'satisfied'],
  ] as const;
  const verdicts = len(x.verdicts, 4).map((item, index) => {
    const q = o(item);
    const result: Verdict = {
      lane: one(q.lane, ['Vulnerable', 'Patched', 'Control A', 'Control B']),
      verdict: one(q.verdict, ['VIOLATED', 'BLOCKED_BY_FIX', 'SATISFIED']),
      color: one(q.color, ['violation', 'blocked', 'satisfied']),
      evidence_digest: d(q.evidence_digest),
    };
    ensure(
      same([result.lane, result.verdict, result.color], verdictSpecs[index]),
      'Verdict mismatch',
    );
    return result;
  });
  return {
    provenance: p,
    hashes: h,
    title: one(x.title, ['Deterministic state exploration']),
    stages,
    tier_counts: tiers(x.tier_counts),
    required_fragments,
    run_markers: markers(x.run_markers),
    verdicts,
  };
};

const parseWorlds = (x: Record<string, unknown>, p: Provenance, h: RunHashes): Worlds => {
  const expectedIds = [
    'root-00',
    ...Array.from({ length: 24 }, (_, index) => `ghost-${String(index + 1).padStart(2, '0')}`),
    ...Array.from({ length: 4 }, (_, index) => `replay-${String(index + 1).padStart(2, '0')}`),
    'simulated-01',
    'simulated-02',
    'materialized-01',
  ];
  const nodes = len(x.nodes, 32).map((item) => {
    const q = o(item);
    return {
      node_id: s(q.node_id),
      tier: one(q.tier, ['ROOT', 'GHOST', 'REPLAY', 'SIMULATED', 'MATERIALIZED']),
      fingerprint: d(q.fingerprint),
      pruned: b(q.pruned),
      status: one(q.status, ['ACTIVE', 'PRUNED', 'RECORDED']),
    } satisfies WorldNode;
  });
  ensure(
    same(
      nodes.map((node) => node.node_id),
      expectedIds,
    ),
    'World ids are not closed',
  );
  ensure(new Set(nodes.map((node) => node.fingerprint)).size === 32, 'Duplicate fingerprint');
  ensure(nodes[0].fingerprint === h.root_hash, 'Root fingerprint mismatch');
  const expectedTiers = { ROOT: 1, GHOST: 24, REPLAY: 4, SIMULATED: 2, MATERIALIZED: 1 };
  for (const [tier, count] of Object.entries(expectedTiers)) {
    ensure(nodes.filter((node) => node.tier === tier).length === count, 'World tier mismatch');
  }
  ensure(nodes.filter((node) => node.pruned).length === 17, 'Pruned world count mismatch');
  for (const node of nodes) {
    const expectedStatus = node.pruned ? 'PRUNED' : node.tier === 'GHOST' ? 'ACTIVE' : 'RECORDED';
    ensure(node.status === expectedStatus, 'World status mismatch');
    ensure(!node.pruned || node.tier === 'GHOST', 'Only Ghost worlds may be pruned');
  }
  const byId = new Map(nodes.map((node) => [node.node_id, node]));
  const relationTiers = {
    explores: ['ROOT', 'GHOST'],
    replays: ['GHOST', 'REPLAY'],
    simulates: ['REPLAY', 'SIMULATED'],
    materializes: ['SIMULATED', 'MATERIALIZED'],
  } as const;
  const relationCounts = { explores: 24, replays: 4, simulates: 4, materializes: 2 } as const;
  const edges = len(x.edges, 34).map((item) => {
    const q = o(item);
    const edge: WorldEdge = {
      from_node_id: s(q.from_node_id),
      to_node_id: s(q.to_node_id),
      relation: one(q.relation, ['explores', 'replays', 'simulates', 'materializes']),
      pruned: b(q.pruned),
    };
    const source = byId.get(edge.from_node_id);
    const target = byId.get(edge.to_node_id);
    ensure(source && target && source.node_id !== target.node_id, 'Invalid world edge');
    ensure(
      same([source.tier, target.tier], relationTiers[edge.relation]),
      'World edge tier mismatch',
    );
    ensure(edge.pruned === (edge.relation === 'explores' && target.pruned), 'Edge prune mismatch');
    return edge;
  });
  ensure(
    new Set(edges.map((edge) => `${edge.from_node_id}|${edge.to_node_id}|${edge.relation}`))
      .size === 34,
    'Duplicate world edge',
  );
  for (const [relation, count] of Object.entries(relationCounts)) {
    ensure(
      edges.filter((edge) => edge.relation === relation).length === count,
      'Edge count mismatch',
    );
  }
  ensure(
    nodes.slice(1).every((node) => edges.some((edge) => edge.to_node_id === node.node_id)),
    'World without parent',
  );
  const inspector = o(x.selected_inspector);
  const parents = len(inspector.parent_node_ids, 2).map(s);
  ensure(same(parents, ['simulated-01', 'simulated-02']), 'Inspector parent mismatch');
  const fingerprint = d(inspector.fingerprint);
  ensure(
    fingerprint === byId.get('materialized-01')?.fingerprint,
    'Inspector fingerprint mismatch',
  );
  return {
    provenance: p,
    hashes: h,
    tier_counts: tiers(x.tier_counts),
    nodes,
    edges,
    selected_inspector: {
      node_id: one(inspector.node_id, ['materialized-01']),
      fingerprint,
      tier: one(inspector.tier, ['MATERIALIZED']),
      parent_node_ids: ['simulated-01', 'simulated-02'],
      status: one(inspector.status, ['SELECTED']),
    },
  };
};

const fact = (value: unknown, label: Fact['label']): Fact => {
  const x = o(value);
  return { label: one(x.label, [label]), summary: s(x.summary), digest: d(x.digest) };
};

const parseTwin = (x: Record<string, unknown>, p: Provenance, h: RunHashes): Twin => {
  const specs = [
    [
      'fragment-a',
      'Fragment A',
      'historic session retained',
      'replay-01',
      'trace-local-fragment-a',
    ],
    [
      'fragment-b',
      'Fragment B',
      'async policy propagation delayed',
      'replay-02',
      'trace-local-fragment-b',
    ],
    [
      'fragment-c',
      'Fragment C',
      'stale authorization decision observed',
      'replay-03',
      'trace-local-fragment-c',
    ],
  ] as const;
  const deltaSpecs = [
    ['session_retention', 'retained', 'retained', 'unchanged'],
    ['policy_propagation', 'delayed', 'propagated', 'updated'],
    ['decision_freshness', 'stale', 'observed', 'recorded'],
  ];
  const fragments = len(x.fragments, 3).map((item, index) => {
    const q = o(item);
    const spec = specs[index];
    const provenance = o(q.provenance);
    const fidelity = o(q.fidelity);
    const trace = o(q.runtime_trace);
    const oracle = o(q.oracle_binding);
    const state_delta = len(q.state_delta, 3).map((delta) => {
      const item = o(delta);
      return {
        field: s(item.field),
        before: s(item.before),
        after: s(item.after),
        effect: s(item.effect),
      };
    });
    ensure(
      same(
        state_delta.map((delta) => [delta.field, delta.before, delta.after, delta.effect]),
        deltaSpecs,
      ),
      'Twin state delta mismatch',
    );
    const fragment: TwinFragment = {
      fragment_id: one(q.fragment_id, ['fragment-a', 'fragment-b', 'fragment-c']),
      label: one(q.label, ['Fragment A', 'Fragment B', 'Fragment C']),
      semantic_label: one(q.semantic_label, [
        'historic session retained',
        'async policy propagation delayed',
        'stale authorization decision observed',
      ]),
      provenance: {
        observation_status: one(provenance.observation_status, ['SYNTHETIC']),
        source_node_id: one(provenance.source_node_id, ['replay-01', 'replay-02', 'replay-03']),
        source_fingerprint: d(provenance.source_fingerprint),
      },
      precondition: fact(q.precondition, 'precondition'),
      typed_action: fact(q.typed_action, 'typed action'),
      effect: fact(q.effect, 'effect'),
      evidence: fact(q.evidence, 'evidence'),
      fidelity: {
        completeness: one(fidelity.completeness, ['fixture-only']),
        ordering: one(fidelity.ordering, ['deterministic fixture']),
        timing: one(fidelity.timing, ['not modeled']),
        determinism: one(fidelity.determinism, ['deterministic']),
      },
      state_delta,
      runtime_trace: {
        trace_id: one(trace.trace_id, [
          'trace-local-fragment-a',
          'trace-local-fragment-b',
          'trace-local-fragment-c',
        ]),
        trace_digest: d(trace.trace_digest),
        runtime: one(trace.runtime, ['local synthetic runtime']),
      },
      oracle_binding: {
        oracle: one(oracle.oracle, ['deterministic']),
        binding_digest: d(oracle.binding_digest),
        oracle_hash: d(oracle.oracle_hash),
      },
    };
    ensure(
      same(
        [
          fragment.fragment_id,
          fragment.label,
          fragment.semantic_label,
          fragment.provenance.source_node_id,
          fragment.runtime_trace.trace_id,
        ],
        spec,
      ),
      'Twin fragment mismatch',
    );
    ensure(fragment.oracle_binding.oracle_hash === h.oracle_hash, 'Twin oracle mismatch');
    return fragment;
  });
  ensure(
    new Set(fragments.map((fragment) => fragment.provenance.source_fingerprint)).size === 3,
    'Twin source fingerprint duplication',
  );
  return {
    provenance: p,
    hashes: h,
    title: one(x.title, ['Security Semantic Twin']),
    fragments,
    selected_fragment_id: one(x.selected_fragment_id, ['fragment-c']),
  };
};

const parseLane = (
  value: unknown,
  laneName: ReplayLane['lane'],
  terminal: ReplayLane['terminal_verdict'],
): ReplayLane => {
  const x = o(value);
  const labels: ReplayStep['label'][] = [
    'Session state retained',
    'Policy state compared',
    'Decision outcome recorded',
  ];
  const steps = len(x.steps, 3).map((item, index) => {
    const q = o(item);
    const sequence = n(q.sequence);
    ensure(sequence === index + 1, 'Replay step sequence mismatch');
    const result: ReplayStep = {
      sequence: sequence as ReplayStep['sequence'],
      label: one(q.label, labels),
      evidence_digest: d(q.evidence_digest),
      verdict: one(q.verdict, ['SATISFIED', 'VIOLATED', 'BLOCKED_BY_FIX']),
    };
    ensure(result.label === labels[index], 'Replay step label mismatch');
    return result;
  });
  ensure(
    steps[0].verdict === 'SATISFIED' && steps[1].verdict === 'SATISFIED',
    'Replay prefix failed',
  );
  ensure(steps[2].verdict === terminal, 'Replay terminal mismatch');
  return {
    lane: one(x.lane, [laneName]),
    plan_hash: d(x.plan_hash),
    steps,
    terminal_verdict: one(x.terminal_verdict, [terminal]),
  };
};

const parseReplay = (x: Record<string, unknown>, p: Provenance, h: RunHashes): Replay => {
  const vulnerable = parseLane(x.vulnerable, 'Vulnerable', 'VIOLATED');
  const patched = parseLane(x.patched, 'Patched', 'BLOCKED_BY_FIX');
  ensure(
    vulnerable.plan_hash === patched.plan_hash && vulnerable.plan_hash === h.plan_hash,
    'Replay plan mismatch',
  );
  const controlSpecs = [
    ['control-a', 'Control A'],
    ['control-b', 'Control B'],
  ] as const;
  const controls = len(x.controls, 2).map((item, index) => {
    const q = o(item);
    const result = {
      control_id: one(q.control_id, ['control-a', 'control-b']),
      label: one(q.label, ['Control A', 'Control B']),
      verdict: one(q.verdict, ['SATISFIED']),
      color: one(q.color, ['satisfied']),
      evidence_digest: d(q.evidence_digest),
    };
    ensure(same([result.control_id, result.label], controlSpecs[index]), 'Control mismatch');
    return result;
  });
  const observation = o(x.selected_observation);
  const selected_observation = {
    label: one(observation.label, ['Observation (redacted)']),
    summary: one(observation.summary, ['synthetic-local decision observation [redacted]']),
    digest: d(observation.digest),
  };
  const manifestSpecs = [
    ['evidence-01', 'Recorded event summary'],
    ['evidence-02', 'Typed state delta'],
    ['evidence-03', 'Oracle comparison'],
    ['evidence-04', 'Policy snapshot'],
    ['evidence-05', 'Replay signature'],
  ] as const;
  const evidence_manifest = len(x.evidence_manifest, 5).map((item, index) => {
    const q = o(item);
    const result = {
      entry_id: one(q.entry_id, [
        'evidence-01',
        'evidence-02',
        'evidence-03',
        'evidence-04',
        'evidence-05',
      ]),
      label: one(q.label, [
        'Recorded event summary',
        'Typed state delta',
        'Oracle comparison',
        'Policy snapshot',
        'Replay signature',
      ]),
      digest: d(q.digest),
      verification: one(q.verification, ['digest-only fixture']),
    };
    ensure(same([result.entry_id, result.label], manifestSpecs[index]), 'Manifest mismatch');
    return result;
  });
  ensure(
    new Set(evidence_manifest.map((entry) => entry.digest)).size === 5,
    'Manifest duplication',
  );
  return {
    provenance: p,
    hashes: h,
    title: one(x.title, ['Clean-root replay']),
    vulnerable,
    patched,
    controls,
    selected_observation,
    evidence_manifest,
    run_markers: markers(x.run_markers),
  };
};

export function parse(
  endpoint: Endpoint,
  value: unknown,
): Health | Overview | Worlds | Twin | Replay {
  const x = o(value);
  const p = prov(x.provenance);
  if (endpoint === '/healthz') {
    return { status: one(x.status, ['ok']), mode: one(x.mode, ['read-only']), provenance: p };
  }
  const h = hashes(x.hashes);
  if (endpoint === '/v1/demo/overview') return parseOverview(x, p, h);
  if (endpoint === '/v1/demo/worlds') return parseWorlds(x, p, h);
  if (endpoint === '/v1/demo/twin') return parseTwin(x, p, h);
  return parseReplay(x, p, h);
}

const fixedManifestSpecs = [
  ['evidence-01', 'Recorded event summary'],
  ['evidence-02', 'Typed state delta'],
  ['evidence-03', 'Oracle comparison'],
  ['evidence-04', 'Policy snapshot'],
  ['evidence-05', 'Replay signature'],
] as const;

async function expectedRunHashes(): Promise<RunHashes> {
  const manifest = await Promise.all(
    fixedManifestSpecs.map(async ([entry_id, label]) => ({
      digest: await canonicalSha256({ entry_id, label, verification: 'digest-only fixture' }),
      entry_id,
      label,
      verification: 'digest-only fixture' as const,
    })),
  );
  return {
    root_hash: await canonicalSha256({
      node_id: 'root-00',
      pruned: false,
      status: 'RECORDED',
      tier: 'ROOT',
    }),
    plan_hash: await canonicalSha256({
      fixture: 'stateweaver-local-plan-v1',
      steps: ['Session state retained', 'Policy state compared', 'Decision outcome recorded'],
    }),
    oracle_hash: await canonicalSha256({
      fixture: 'stateweaver-local-oracle-v1',
      invariant: 'patched lane blocks the synthetic terminal condition',
    }),
    evidence_hash: await canonicalSha256(manifest),
  };
}

async function assertRunHashes(hashes: RunHashes): Promise<void> {
  ensure(same(hashes, await expectedRunHashes()), 'Run hashes do not bind the built-in fixture');
}

async function assertMarkerDigests(
  values: Marker[],
  h: RunHashes,
  vulnerable: 'VIOLATED',
  patched: 'BLOCKED_BY_FIX',
): Promise<void> {
  const expected = await canonicalSha256({
    oracle_hash: h.oracle_hash,
    patched,
    plan_hash: h.plan_hash,
    root_hash: h.root_hash,
    vulnerable,
  });
  ensure(
    values.every((marker) => marker.signature === expected),
    'Run signature does not bind fixture hashes and verdicts',
  );
}

async function assertOverviewContent(overview: Overview): Promise<void> {
  await assertRunHashes(overview.hashes);
  await Promise.all(
    overview.stages.map((stage) =>
      digestMatches(
        stage.evidence_digest,
        { label: stage.label, sequence: stage.sequence, status: stage.status },
        'Stage digest mismatch',
      ),
    ),
  );
  await Promise.all(
    overview.required_fragments.map((fragment) =>
      digestMatches(
        fragment.evidence_digest,
        {
          fragment_id: fragment.fragment_id,
          label: fragment.label,
          semantic_label: fragment.semantic_label,
        },
        'Required fragment digest mismatch',
      ),
    ),
  );
  await Promise.all(
    overview.verdicts.map((verdict) =>
      digestMatches(
        verdict.evidence_digest,
        { color: verdict.color, lane: verdict.lane, verdict: verdict.verdict },
        'Verdict digest mismatch',
      ),
    ),
  );
  await assertMarkerDigests(overview.run_markers, overview.hashes, 'VIOLATED', 'BLOCKED_BY_FIX');
}

async function assertWorldContent(worlds: Worlds): Promise<void> {
  await assertRunHashes(worlds.hashes);
  await Promise.all(
    worlds.nodes.map((node) =>
      digestMatches(
        node.fingerprint,
        {
          node_id: node.node_id,
          pruned: node.pruned,
          status: node.status,
          tier: node.tier,
        },
        'World fingerprint mismatch',
      ),
    ),
  );
  const expectedEdges = [
    ...Array.from({ length: 24 }, (_, index) => [
      'root-00',
      `ghost-${String(index + 1).padStart(2, '0')}`,
      'explores',
      index < 17,
    ]),
    ['ghost-18', 'replay-01', 'replays', false],
    ['ghost-21', 'replay-02', 'replays', false],
    ['ghost-22', 'replay-03', 'replays', false],
    ['ghost-24', 'replay-04', 'replays', false],
    ['replay-01', 'simulated-01', 'simulates', false],
    ['replay-02', 'simulated-01', 'simulates', false],
    ['replay-03', 'simulated-02', 'simulates', false],
    ['replay-04', 'simulated-02', 'simulates', false],
    ['simulated-01', 'materialized-01', 'materializes', false],
    ['simulated-02', 'materialized-01', 'materializes', false],
  ];
  ensure(
    same(
      worlds.edges.map((edge) => [edge.from_node_id, edge.to_node_id, edge.relation, edge.pruned]),
      expectedEdges,
    ),
    'World edges do not match the built-in fixture',
  );
}

async function assertTwinContent(twin: Twin): Promise<void> {
  await assertRunHashes(twin.hashes);
  const factSpecs = [
    ['precondition', 'recorded local state is available'],
    ['typed action', 'compare recorded typed state'],
    ['effect', 'recorded state transition is displayed'],
    ['evidence', 'saved synthetic evidence is bound'],
  ] as const;
  for (const fragment of twin.fragments) {
    const facts = [
      fragment.precondition,
      fragment.typed_action,
      fragment.effect,
      fragment.evidence,
    ];
    ensure(
      same(
        facts.map((fact) => [fact.label, fact.summary]),
        factSpecs,
      ),
      'Twin facts do not match the built-in fixture',
    );
    await Promise.all(
      facts.map((fact) =>
        digestMatches(
          fact.digest,
          { label: fact.label, summary: fact.summary },
          'Twin fact digest mismatch',
        ),
      ),
    );
    await digestMatches(
      fragment.provenance.source_fingerprint,
      {
        node_id: fragment.provenance.source_node_id,
        pruned: false,
        status: 'RECORDED',
        tier: 'REPLAY',
      },
      'Twin source fingerprint mismatch',
    );
    await digestMatches(
      fragment.runtime_trace.trace_digest,
      {
        runtime: fragment.runtime_trace.runtime,
        trace_id: fragment.runtime_trace.trace_id,
      },
      'Twin trace digest mismatch',
    );
    await digestMatches(
      fragment.oracle_binding.binding_digest,
      {
        oracle: fragment.oracle_binding.oracle,
        oracle_hash: fragment.oracle_binding.oracle_hash,
      },
      'Twin oracle binding digest mismatch',
    );
  }
}

async function assertReplayContent(replay: Replay): Promise<void> {
  await assertRunHashes(replay.hashes);
  await Promise.all(
    [...replay.vulnerable.steps, ...replay.patched.steps].map((step) =>
      digestMatches(
        step.evidence_digest,
        { label: step.label, sequence: step.sequence, verdict: step.verdict },
        'Replay step digest mismatch',
      ),
    ),
  );
  await Promise.all(
    replay.controls.map((control) =>
      digestMatches(
        control.evidence_digest,
        {
          color: control.color,
          control_id: control.control_id,
          label: control.label,
          verdict: control.verdict,
        },
        'Control digest mismatch',
      ),
    ),
  );
  await digestMatches(
    replay.selected_observation.digest,
    {
      label: replay.selected_observation.label,
      summary: replay.selected_observation.summary,
    },
    'Observation digest mismatch',
  );
  await Promise.all(
    replay.evidence_manifest.map((entry) =>
      digestMatches(
        entry.digest,
        { entry_id: entry.entry_id, label: entry.label, verification: entry.verification },
        'Manifest entry digest mismatch',
      ),
    ),
  );
  await digestMatches(
    replay.hashes.evidence_hash,
    replay.evidence_manifest,
    'Evidence hash does not bind the canonical manifest',
  );
  await assertMarkerDigests(replay.run_markers, replay.hashes, 'VIOLATED', 'BLOCKED_BY_FIX');
}

async function assertEndpointContent(
  endpoint: Endpoint,
  value: Health | Overview | Worlds | Twin | Replay,
): Promise<void> {
  if (endpoint === '/healthz') return;
  if (endpoint === '/v1/demo/overview') return assertOverviewContent(value as Overview);
  if (endpoint === '/v1/demo/worlds') return assertWorldContent(value as Worlds);
  if (endpoint === '/v1/demo/twin') return assertTwinContent(value as Twin);
  return assertReplayContent(value as Replay);
}

export async function assertFixtureBundle(
  overview: Overview,
  worlds: Worlds,
  twin: Twin,
  replay: Replay,
): Promise<void> {
  await Promise.all([
    assertOverviewContent(overview),
    assertWorldContent(worlds),
    assertTwinContent(twin),
    assertReplayContent(replay),
  ]);
  const responses = [worlds, twin, replay];
  ensure(
    responses.every((response) => same(response.hashes, overview.hashes)),
    'Fixture endpoints describe different runs',
  );
  ensure(
    same(worlds.tier_counts, overview.tier_counts),
    'Overview and World DAG tier counts differ',
  );
  ensure(
    twin.fragments.every((fragment, index) => {
      const required = overview.required_fragments[index];
      const source = worlds.nodes.find(
        (node) => node.node_id === fragment.provenance.source_node_id,
      );
      return (
        required.fragment_id === fragment.fragment_id &&
        required.label === fragment.label &&
        required.semantic_label === fragment.semantic_label &&
        source?.fingerprint === fragment.provenance.source_fingerprint
      );
    }),
    'Twin fragments do not bind overview requirements and source worlds',
  );
  ensure(
    same(overview.run_markers, replay.run_markers),
    'Overview and replay markers describe different runs',
  );
  ensure(
    overview.verdicts[0].verdict === replay.vulnerable.terminal_verdict &&
      overview.verdicts[1].verdict === replay.patched.terminal_verdict,
    'Overview and replay verdicts differ',
  );
}

export async function get<T>(endpoint: Endpoint): Promise<T> {
  const response = await fetch(endpoint, {
    method: 'GET',
    headers: { Accept: 'application/json' },
  });
  if (!response.ok) throw Error(`Fixture request failed (${response.status})`);
  const parsed = parse(endpoint, await response.json());
  await assertEndpointContent(endpoint, parsed);
  return parsed as T;
}
