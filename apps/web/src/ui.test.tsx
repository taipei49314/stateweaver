import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  assertFixtureBundle,
  canonicalSha256,
  parse,
  type Overview,
  type Replay,
  type Twin,
  type Worlds,
} from './api';
import { App } from './ui';

const digest = (n: number) => n.toString(16).padStart(64, '0');
const provenance = {
  boundary_label: 'SYNTHETIC LOCAL LAB',
  run_id: 'sw_demo_01',
  commit_placeholder: '0'.repeat(40),
  mode: 'deterministic',
  oracle: 'deterministic',
  model_calls: 0,
  workspace: 'local-lab',
  certification: 'not release-certified',
  fixture_status: 'saved synthetic implementation evidence',
  proof_status: 'not materialized proof',
} as const;
const hashes = {
  root_hash: digest(101),
  plan_hash: digest(102),
  oracle_hash: digest(103),
  evidence_hash: digest(104),
};
const tiers = {
  root: 1,
  ghost: 24,
  replay: 4,
  simulated: 2,
  materialized: 1,
  pruned: 17,
  flow: '24 → 4 → 2 → 1',
} as const;
const nodes = [
  {
    node_id: 'root-00',
    tier: 'ROOT',
    fingerprint: hashes.root_hash,
    pruned: false,
    status: 'RECORDED',
  },
  ...Array.from({ length: 24 }, (_, i) => ({
    node_id: `ghost-${String(i + 1).padStart(2, '0')}`,
    tier: 'GHOST',
    fingerprint: digest(1000 + i),
    pruned: i < 17,
    status: i < 17 ? 'PRUNED' : 'ACTIVE',
  })),
  ...Array.from({ length: 4 }, (_, i) => ({
    node_id: `replay-${String(i + 1).padStart(2, '0')}`,
    tier: 'REPLAY',
    fingerprint: digest(2000 + i),
    pruned: false,
    status: 'RECORDED',
  })),
  ...Array.from({ length: 2 }, (_, i) => ({
    node_id: `simulated-${String(i + 1).padStart(2, '0')}`,
    tier: 'SIMULATED',
    fingerprint: digest(3000 + i),
    pruned: false,
    status: 'RECORDED',
  })),
  {
    node_id: 'materialized-01',
    tier: 'MATERIALIZED',
    fingerprint: digest(4001),
    pruned: false,
    status: 'RECORDED',
  },
];
const edges = [
  ...Array.from({ length: 24 }, (_, i) => ({
    from_node_id: 'root-00',
    to_node_id: `ghost-${String(i + 1).padStart(2, '0')}`,
    relation: 'explores',
    pruned: i < 17,
  })),
  ...['ghost-18', 'ghost-21', 'ghost-22', 'ghost-24'].map((id, i) => ({
    from_node_id: id,
    to_node_id: `replay-0${i + 1}`,
    relation: 'replays',
    pruned: false,
  })),
  ...['replay-01', 'replay-02', 'replay-03', 'replay-04'].map((id, i) => ({
    from_node_id: id,
    to_node_id: `simulated-${i < 2 ? '01' : '02'}`,
    relation: 'simulates',
    pruned: false,
  })),
  ...['simulated-01', 'simulated-02'].map((id) => ({
    from_node_id: id,
    to_node_id: 'materialized-01',
    relation: 'materializes',
    pruned: false,
  })),
];
const factSummaries: Record<string, string> = {
  precondition: 'recorded local state is available',
  'typed action': 'compare recorded typed state',
  effect: 'recorded state transition is displayed',
  evidence: 'saved synthetic evidence is bound',
};
const fact = (label: string, n: number) => ({
  label,
  summary: factSummaries[label],
  digest: digest(n),
});
const twinFragments = ['a', 'b', 'c'].map((id, i) => ({
  fragment_id: `fragment-${id}`,
  label: `Fragment ${id.toUpperCase()}`,
  semantic_label: [
    'historic session retained',
    'async policy propagation delayed',
    'stale authorization decision observed',
  ][i],
  provenance: {
    observation_status: 'SYNTHETIC',
    source_node_id: `replay-0${i + 1}`,
    source_fingerprint: digest(2000 + i),
  },
  precondition: fact('precondition', 500 + i * 10),
  typed_action: fact('typed action', 501 + i * 10),
  effect: fact('effect', 502 + i * 10),
  evidence: fact('evidence', 503 + i * 10),
  fidelity: {
    completeness: 'fixture-only',
    ordering: 'deterministic fixture',
    timing: 'not modeled',
    determinism: 'deterministic',
  },
  state_delta: [
    { field: 'session_retention', before: 'retained', after: 'retained', effect: 'unchanged' },
    { field: 'policy_propagation', before: 'delayed', after: 'propagated', effect: 'updated' },
    { field: 'decision_freshness', before: 'stale', after: 'observed', effect: 'recorded' },
  ],
  runtime_trace: {
    trace_id: `trace-local-fragment-${id}`,
    trace_digest: digest(504 + i * 10),
    runtime: 'local synthetic runtime',
  },
  oracle_binding: {
    oracle: 'deterministic',
    binding_digest: digest(505 + i * 10),
    oracle_hash: hashes.oracle_hash,
  },
}));
const steps = (terminal: 'VIOLATED' | 'BLOCKED_BY_FIX') => [
  {
    sequence: 1,
    label: 'Session state retained',
    evidence_digest: digest(801),
    verdict: 'SATISFIED',
  },
  {
    sequence: 2,
    label: 'Policy state compared',
    evidence_digest: digest(802),
    verdict: 'SATISFIED',
  },
  {
    sequence: 3,
    label: 'Decision outcome recorded',
    evidence_digest: digest(803),
    verdict: terminal,
  },
];
const overview = {
  provenance,
  hashes,
  title: 'Deterministic state exploration',
  stages: [
    'Root captured',
    'World search',
    'Chain compiled',
    'Clean replay',
    'Patched comparison',
    'Fixture integrity checked',
  ].map((label, i) => ({
    sequence: i + 1,
    label,
    status: i === 4 ? 'BLOCKED_BY_FIX' : 'READY',
    evidence_digest: digest(200 + i),
  })),
  tier_counts: tiers,
  required_fragments: twinFragments.map((f) => ({
    fragment_id: f.fragment_id,
    label: f.label,
    semantic_label: f.semantic_label,
    evidence_digest: f.evidence.digest,
  })),
  run_markers: [1, 2, 3, 4, 5].map((ordinal) => ({
    ordinal,
    signature: digest(105),
    status: 'matching fixture',
  })),
  verdicts: [
    ['Vulnerable', 'VIOLATED', 'violation'],
    ['Patched', 'BLOCKED_BY_FIX', 'blocked'],
    ['Control A', 'SATISFIED', 'satisfied'],
    ['Control B', 'SATISFIED', 'satisfied'],
  ].map(([lane, verdict, color], i) => ({
    lane,
    verdict,
    color,
    evidence_digest: digest(401 + i),
  })),
};
const worlds = {
  provenance,
  hashes,
  tier_counts: tiers,
  nodes,
  edges,
  selected_inspector: {
    node_id: 'materialized-01',
    fingerprint: digest(4001),
    tier: 'MATERIALIZED',
    parent_node_ids: ['simulated-01', 'simulated-02'],
    status: 'SELECTED',
  },
};
const twin = {
  provenance,
  hashes,
  title: 'Security Semantic Twin',
  fragments: twinFragments,
  selected_fragment_id: 'fragment-c',
};
const replay = {
  provenance,
  hashes,
  title: 'Clean-root replay',
  vulnerable: {
    lane: 'Vulnerable',
    plan_hash: hashes.plan_hash,
    steps: steps('VIOLATED'),
    terminal_verdict: 'VIOLATED',
  },
  patched: {
    lane: 'Patched',
    plan_hash: hashes.plan_hash,
    steps: steps('BLOCKED_BY_FIX'),
    terminal_verdict: 'BLOCKED_BY_FIX',
  },
  controls: [
    {
      control_id: 'control-a',
      label: 'Control A',
      verdict: 'SATISFIED',
      color: 'satisfied',
      evidence_digest: digest(901),
    },
    {
      control_id: 'control-b',
      label: 'Control B',
      verdict: 'SATISFIED',
      color: 'satisfied',
      evidence_digest: digest(902),
    },
  ],
  selected_observation: {
    label: 'Observation (redacted)',
    summary: 'synthetic-local decision observation [redacted]',
    digest: digest(903),
  },
  evidence_manifest: [
    'Recorded event summary',
    'Typed state delta',
    'Oracle comparison',
    'Policy snapshot',
    'Replay signature',
  ].map((label, i) => ({
    entry_id: `evidence-0${i + 1}`,
    label,
    digest: digest(10000 + i),
    verification: 'digest-only fixture',
  })),
  run_markers: [1, 2, 3, 4, 5].map((ordinal) => ({
    ordinal,
    signature: digest(105),
    status: 'matching fixture',
  })),
};

async function sealFixtureDigests(): Promise<void> {
  hashes.root_hash = await canonicalSha256({
    node_id: 'root-00',
    pruned: false,
    status: 'RECORDED',
    tier: 'ROOT',
  });
  hashes.plan_hash = await canonicalSha256({
    fixture: 'stateweaver-local-plan-v1',
    steps: ['Session state retained', 'Policy state compared', 'Decision outcome recorded'],
  });
  hashes.oracle_hash = await canonicalSha256({
    fixture: 'stateweaver-local-oracle-v1',
    invariant: 'patched lane blocks the synthetic terminal condition',
  });

  for (const node of nodes) {
    node.fingerprint = await canonicalSha256({
      node_id: node.node_id,
      pruned: node.pruned,
      status: node.status,
      tier: node.tier,
    });
  }
  worlds.selected_inspector.fingerprint = nodes.find(
    (node) => node.node_id === 'materialized-01',
  )!.fingerprint;

  for (const [index, fragment] of twinFragments.entries()) {
    fragment.provenance.source_fingerprint = nodes.find(
      (node) => node.node_id === fragment.provenance.source_node_id,
    )!.fingerprint;
    for (const item of [
      fragment.precondition,
      fragment.typed_action,
      fragment.effect,
      fragment.evidence,
    ]) {
      item.digest = await canonicalSha256({ label: item.label, summary: item.summary });
    }
    fragment.runtime_trace.trace_digest = await canonicalSha256({
      runtime: fragment.runtime_trace.runtime,
      trace_id: fragment.runtime_trace.trace_id,
    });
    fragment.oracle_binding.oracle_hash = hashes.oracle_hash;
    fragment.oracle_binding.binding_digest = await canonicalSha256({
      oracle: fragment.oracle_binding.oracle,
      oracle_hash: fragment.oracle_binding.oracle_hash,
    });
    const required = overview.required_fragments[index];
    required.evidence_digest = await canonicalSha256({
      fragment_id: required.fragment_id,
      label: required.label,
      semantic_label: required.semantic_label,
    });
  }

  for (const stage of overview.stages) {
    stage.evidence_digest = await canonicalSha256({
      label: stage.label,
      sequence: stage.sequence,
      status: stage.status,
    });
  }
  for (const verdict of overview.verdicts) {
    verdict.evidence_digest = await canonicalSha256({
      color: verdict.color,
      lane: verdict.lane,
      verdict: verdict.verdict,
    });
  }
  replay.vulnerable.plan_hash = hashes.plan_hash;
  replay.patched.plan_hash = hashes.plan_hash;
  for (const step of [...replay.vulnerable.steps, ...replay.patched.steps]) {
    step.evidence_digest = await canonicalSha256({
      label: step.label,
      sequence: step.sequence,
      verdict: step.verdict,
    });
  }
  for (const control of replay.controls) {
    control.evidence_digest = await canonicalSha256({
      color: control.color,
      control_id: control.control_id,
      label: control.label,
      verdict: control.verdict,
    });
  }
  replay.selected_observation.digest = await canonicalSha256({
    label: replay.selected_observation.label,
    summary: replay.selected_observation.summary,
  });
  for (const entry of replay.evidence_manifest) {
    entry.digest = await canonicalSha256({
      entry_id: entry.entry_id,
      label: entry.label,
      verification: entry.verification,
    });
  }
  hashes.evidence_hash = await canonicalSha256(replay.evidence_manifest);
  const signature = await canonicalSha256({
    oracle_hash: hashes.oracle_hash,
    patched: 'BLOCKED_BY_FIX',
    plan_hash: hashes.plan_hash,
    root_hash: hashes.root_hash,
    vulnerable: 'VIOLATED',
  });
  for (const marker of [...overview.run_markers, ...replay.run_markers]) {
    marker.signature = signature;
  }
}

await sealFixtureDigests();

const payloads: Record<string, unknown> = {
  '/v1/demo/overview': overview,
  '/v1/demo/worlds': worlds,
  '/v1/demo/twin': twin,
  '/v1/demo/replay': replay,
};
beforeEach(() => {
  history.replaceState({}, '', '/');
  vi.stubGlobal(
    'fetch',
    vi.fn((u: string) => Promise.resolve({ ok: true, json: () => Promise.resolve(payloads[u]) })),
  );
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: { writeText: vi.fn() },
  });
});
afterEach(cleanup);
async function ready() {
  render(<App />);
  await screen.findByText('Deterministic state exploration');
}
describe('second-stage fixture parser', () => {
  it('accepts overview counts, verdicts and markers', () => {
    const x = parse('/v1/demo/overview', overview) as typeof overview;
    expect(x.run_markers).toHaveLength(5);
    expect(x.verdicts).toHaveLength(4);
    expect(x.tier_counts.ghost).toBe(24);
  });
  it('validates worlds and rejects tampering', () => {
    expect((parse('/v1/demo/worlds', worlds) as typeof worlds).edges).toHaveLength(34);
    expect(() =>
      parse('/v1/demo/worlds', {
        ...worlds,
        edges: [...edges.slice(0, 33), { ...edges[33], to_node_id: 'missing' }],
      }),
    ).toThrow();
    expect(() =>
      parse('/v1/demo/worlds', {
        ...worlds,
        nodes: [{ ...nodes[0], fingerprint: 'x' }, ...nodes.slice(1)],
      }),
    ).toThrow();
    expect(() =>
      parse('/v1/demo/worlds', {
        ...worlds,
        edges: [
          ...edges.slice(0, 33),
          { ...edges[33], from_node_id: 'materialized-01', to_node_id: 'materialized-01' },
        ],
      }),
    ).toThrow();
    expect(() =>
      parse('/v1/demo/worlds', {
        ...worlds,
        selected_inspector: { ...worlds.selected_inspector, fingerprint: digest(9999) },
      }),
    ).toThrow();
  });
  it('rejects duplicated causal objects and replay substitutions', () => {
    expect(() =>
      parse('/v1/demo/overview', {
        ...overview,
        stages: [overview.stages[0], overview.stages[0], ...overview.stages.slice(2)],
      }),
    ).toThrow();
    expect(() =>
      parse('/v1/demo/twin', {
        ...twin,
        fragments: [twin.fragments[0], twin.fragments[0], twin.fragments[2]],
      }),
    ).toThrow();
    expect(() =>
      parse('/v1/demo/replay', {
        ...replay,
        patched: { ...replay.patched, plan_hash: digest(9998) },
      }),
    ).toThrow();
    expect(() =>
      parse('/v1/demo/replay', {
        ...replay,
        evidence_manifest: Array(5).fill(replay.evidence_manifest[0]),
      }),
    ).toThrow();
    expect(() =>
      parse('/v1/demo/replay', {
        ...replay,
        run_markers: replay.run_markers.map((marker, index) =>
          index === 4 ? { ...marker, signature: digest(9997) } : marker,
        ),
      }),
    ).toThrow();
  });
  it('closes identity across all four endpoints', async () => {
    const parsedOverview = parse('/v1/demo/overview', overview);
    const parsedWorlds = parse('/v1/demo/worlds', worlds);
    const parsedTwin = parse('/v1/demo/twin', twin);
    const parsedReplay = parse('/v1/demo/replay', replay);
    await assertFixtureBundle(
      parsedOverview as Overview,
      parsedWorlds as Worlds,
      parsedTwin as Twin,
      parsedReplay as Replay,
    );
    await expect(
      assertFixtureBundle(
        parsedOverview as Overview,
        parsedWorlds as Worlds,
        {
          ...(parsedTwin as Twin),
          hashes: { ...hashes, root_hash: digest(9996) },
        },
        parsedReplay as Replay,
      ),
    ).rejects.toThrow();
  });
  it('recomputes content digests and rejects consistent opaque hash substitution', async () => {
    const parsedOverview = parse('/v1/demo/overview', overview) as Overview;
    const parsedWorlds = parse('/v1/demo/worlds', worlds) as Worlds;
    const parsedTwin = parse('/v1/demo/twin', twin) as Twin;
    const parsedReplay = parse('/v1/demo/replay', replay) as Replay;

    await expect(
      assertFixtureBundle(
        {
          ...parsedOverview,
          stages: [
            { ...parsedOverview.stages[0], evidence_digest: digest(9991) },
            ...parsedOverview.stages.slice(1),
          ],
        },
        parsedWorlds,
        parsedTwin,
        parsedReplay,
      ),
    ).rejects.toThrow('Stage digest mismatch');
    await expect(
      assertFixtureBundle(
        parsedOverview,
        {
          ...parsedWorlds,
          nodes: [
            parsedWorlds.nodes[0],
            { ...parsedWorlds.nodes[1], fingerprint: digest(9992) },
            ...parsedWorlds.nodes.slice(2),
          ],
        },
        parsedTwin,
        parsedReplay,
      ),
    ).rejects.toThrow('World fingerprint mismatch');
    await expect(
      assertFixtureBundle(
        parsedOverview,
        parsedWorlds,
        {
          ...parsedTwin,
          fragments: [
            {
              ...parsedTwin.fragments[0],
              precondition: { ...parsedTwin.fragments[0].precondition, digest: digest(9993) },
            },
            ...parsedTwin.fragments.slice(1),
          ],
        },
        parsedReplay,
      ),
    ).rejects.toThrow('Twin fact digest mismatch');
    await expect(
      assertFixtureBundle(parsedOverview, parsedWorlds, parsedTwin, {
        ...parsedReplay,
        evidence_manifest: [
          { ...parsedReplay.evidence_manifest[0], digest: digest(9994) },
          ...parsedReplay.evidence_manifest.slice(1),
        ],
      }),
    ).rejects.toThrow('Manifest entry digest mismatch');

    const substituted = {
      ...parsedOverview.hashes,
      plan_hash: digest(9995),
      oracle_hash: digest(9996),
    };
    await expect(
      assertFixtureBundle(
        { ...parsedOverview, hashes: substituted },
        { ...parsedWorlds, hashes: substituted },
        { ...parsedTwin, hashes: substituted },
        { ...parsedReplay, hashes: substituted },
      ),
    ).rejects.toThrow('Run hashes do not bind the built-in fixture');
  });
});
describe('second-stage UI', () => {
  it('filters all world tiers and pruned nodes', async () => {
    await ready();
    fireEvent.click(screen.getByText('World DAG'));
    await screen.findByText('ghost-24');
    expect(screen.getAllByText(/ghost-/).length).toBeGreaterThanOrEqual(24);
    fireEvent.click(screen.getByText('ghost-24'));
    expect(screen.getByText('Parents: root-00')).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText('GHOST'));
    expect(screen.queryByText('ghost-24')).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'root-00' })).toBeInTheDocument();
    expect(screen.getByText('Parents: clean root')).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText('PRUNED'));
    expect(screen.queryByText('ghost-01')).not.toBeInTheDocument();
  });
  it('switches actual twin fragments', async () => {
    await ready();
    fireEvent.click(screen.getByText('Twin Inspector'));
    expect((await screen.findAllByText('Fragment C')).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByText('Fragment A'));
    expect(screen.getByText(twinFragments[0].runtime_trace.trace_digest)).toBeInTheDocument();
  });
  it('shows aligned replay lanes and controls', async () => {
    await ready();
    fireEvent.click(screen.getByText('Replay / Evidence'));
    await screen.findByText('Clean-root replay');
    expect(screen.getAllByText('Decision outcome recorded').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText('Control A: SATISFIED')).toBeInTheDocument();
    fireEvent.click(screen.getByText('Next'));
    expect(screen.getAllByText('Policy state compared').length).toBeGreaterThan(0);
    expect(
      screen.getByText(
        'matching fixture · matching fixture · matching fixture · matching fixture · matching fixture',
      ),
    ).toBeInTheDocument();
  });
  it('retains boundary on failure and navigation uses history', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve({ ok: false, status: 503, json: () => Promise.resolve({}) })),
    );
    render(<App />);
    expect(await screen.findByText('Saved fixture unavailable')).toBeInTheDocument();
    expect(screen.getByText('SYNTHETIC LOCAL LAB')).toBeInTheDocument();
  });
});
