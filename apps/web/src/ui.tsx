import { useEffect, useState } from 'react';
import {
  assertFixtureBundle,
  canonicalSha256,
  get,
  type Overview,
  type Replay,
  type Twin,
  type Worlds,
} from './api';
type Route = 'overview' | 'worlds' | 'twin' | 'replay';
const nav: [Route, string][] = [
  ['overview', 'Experiment Overview'],
  ['worlds', 'World DAG'],
  ['twin', 'Twin Inspector'],
  ['replay', 'Replay / Evidence'],
];
const path = (r: Route) => (r === 'overview' ? '/' : `/${r}`);
const route = (): Route =>
  location.pathname.includes('worlds')
    ? 'worlds'
    : location.pathname.includes('twin')
      ? 'twin'
      : location.pathname.includes('replay')
        ? 'replay'
        : 'overview';
function I({ n }: { n: string }) {
  return (
    <svg className="icon" viewBox="0 0 24 24" aria-hidden="true">
      <path d={n === 'play' ? 'm8 5 11 7-11 7z' : 'M4 4h16v16H4zM4 12h16M12 4v16'} />
    </svg>
  );
}
function Copy({ v }: { v: string }) {
  const [c, setC] = useState(false);
  return (
    <button
      className="copy"
      aria-label={c ? 'Copied' : 'Copy hash'}
      onClick={() => {
        void navigator.clipboard?.writeText(v);
        setC(true);
      }}
    >
      <I n="copy" />
    </button>
  );
}
function Hash({ v }: { v: string }) {
  return (
    <span className="hash">
      {v}
      <Copy v={v} />
    </span>
  );
}
function Mark({ v }: { v: string }) {
  return (
    <span
      className={`mark ${v === 'VIOLATED' ? 'bad' : v === 'BLOCKED_BY_FIX' ? 'blocked' : 'ready'}`}
    />
  );
}
function Shell({
  r,
  set,
  children,
  p,
}: {
  r: Route;
  set: (r: Route) => void;
  children: React.ReactNode;
  p?: Overview['provenance'];
}) {
  return (
    <div className="app">
      <header>
        <div className="brand">
          <svg className="icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="m3 8 9-5 9 5-9 5zM3 12l9 5 9-5M3 16l9 5 9-5" />
          </svg>
          <strong>StateWeaver</strong>
          <span className="boundary">LOCAL SYNTHETIC LAB</span>
        </div>
        <div className="run">
          RUN <b>{p?.run_id}</b> COMMIT <b>{p?.commit_placeholder.slice(0, 8)}</b>
        </div>
      </header>
      <aside className="nav">
        <nav aria-label="Primary workspace">
          {nav.map(([id, label]) => (
            <button
              aria-current={id === r ? 'page' : undefined}
              className={id === r ? 'chosen' : ''}
              key={id}
              onClick={() => set(id)}
            >
              <I n="nav" />
              {label}
            </button>
          ))}
        </nav>
      </aside>
      <main>{children}</main>
      <footer>
        READY <span>Mode: Deterministic</span>
        <span>Oracle: deterministic</span>
        <span>Model calls: 0</span>
        <span>Workspace: local-lab</span>
      </footer>
    </div>
  );
}
function Loading({ e }: { e?: string }) {
  return (
    <section className="boundary-state">
      <span className="boundary">SYNTHETIC LOCAL LAB</span>
      <h1>{e ? 'Saved fixture unavailable' : 'Loading saved fixture'}</h1>
      <p>{e}</p>
    </section>
  );
}
function OverviewPage({ d, set }: { d: Overview; set: (r: Route) => void }) {
  return (
    <section className="overview">
      <div className="workspace-title">
        <h1>{d.title}</h1>
        <p>
          {d.provenance.fixture_status} · {d.provenance.certification}
        </p>
      </div>
      <div className="spine">
        {d.stages.map((s) => (
          <article key={s.sequence}>
            <span className="stage-icon">{String(s.sequence).padStart(2, '0')}</span>
            <strong>{s.label}</strong>
            <small>{s.status.replaceAll('_', ' ')}</small>
            <Hash v={s.evidence_digest} />
          </article>
        ))}
      </div>
      <section className="band counts" aria-label="World tier summary" tabIndex={0}>
        <h2>World tiers</h2>
        {[
          ['24', 'World search'],
          ['4', 'Chain compiled'],
          ['2', 'Clean replay'],
          ['1', 'Fixture integrity checked'],
        ].map((x) => (
          <div key={x[1]}>
            <b>{x[0]}</b>
            <span>{x[1]}</span>
          </div>
        ))}
      </section>
      <section className="band fragments">
        <div>
          <h2>Required fragments</h2>
          <p>3 required fragments</p>
        </div>
        {d.required_fragments.map((f) => (
          <article className="fragment" key={f.fragment_id}>
            <button className="fragment-open" onClick={() => set('twin')}>
              <b>{f.label.slice(-1)}</b>
              <span>
                {f.label}
                <small>{f.semantic_label}</small>
              </span>
            </button>
            <Hash v={f.evidence_digest} />
          </article>
        ))}
      </section>
      <section className="verdicts">
        {d.verdicts.map((v) => (
          <article className={`verdict ${v.color}`} key={v.lane}>
            <h3>
              <Mark v={v.verdict} />
              {v.lane}: {v.verdict.replaceAll('_', ' ')}
            </h3>
            <Hash v={v.evidence_digest} />
          </article>
        ))}
      </section>
      <div className="actions">
        <button onClick={() => set('worlds')}>Open World DAG</button>
        <button onClick={() => set('replay')}>Replay finding</button>
      </div>
    </section>
  );
}
function WorldsPage({ d }: { d: Worlds }) {
  const [tiers, setT] = useState<string[]>([
    'ROOT',
    'GHOST',
    'REPLAY',
    'SIMULATED',
    'MATERIALIZED',
  ]);
  const [pruned, setP] = useState(true);
  const [selected, setS] = useState<string>(d.selected_inspector.node_id);
  const shown = d.nodes.filter((n) => tiers.includes(n.tier) && (pruned || !n.pruned));
  const selectedNode = shown.find((node) => node.node_id === selected) ?? shown[0];
  const selectedParents = d.edges
    .filter((edge) => edge.to_node_id === selectedNode?.node_id)
    .map((edge) => edge.from_node_id);
  return (
    <section className="worlds">
      <div className="toolbar">
        <button
          onClick={() => {
            setT(['ROOT', 'GHOST', 'REPLAY', 'SIMULATED', 'MATERIALIZED']);
            setP(true);
          }}
        >
          Fit
        </button>
        {['ROOT', 'GHOST', 'REPLAY', 'SIMULATED', 'MATERIALIZED'].map((t) => (
          <label key={t}>
            <input
              type="checkbox"
              checked={tiers.includes(t)}
              onChange={() => setT((x) => (x.includes(t) ? x.filter((y) => y !== t) : [...x, t]))}
            />
            {t}
          </label>
        ))}
        <label>
          <input type="checkbox" checked={pruned} onChange={(e) => setP(e.target.checked)} />
          PRUNED
        </label>
      </div>
      <div className="dag">
        {shown.map((n) => (
          <button
            className={`dag-node ${n.node_id === selectedNode?.node_id ? 'selected' : ''}`}
            onClick={() => setS(n.node_id)}
            key={n.node_id}
          >
            <Mark v={n.pruned ? 'BLOCKED_BY_FIX' : 'READY'} />
            <b>{n.node_id}</b>
            <small>
              {n.tier} · {n.status}
            </small>
          </button>
        ))}
      </div>
      <aside className="inspector">
        <small>SELECTED NODE</small>
        <h2>{selectedNode?.node_id ?? 'No visible node'}</h2>
        {selectedNode ? (
          <Hash v={selectedNode.fingerprint} />
        ) : (
          <p>Enable a world tier to inspect.</p>
        )}
        {selectedNode && (
          <p>Parents: {selectedParents.length ? selectedParents.join(', ') : 'clean root'}</p>
        )}
        <p>{d.edges.length} fixture edges</p>
      </aside>
    </section>
  );
}
function TwinPage({ d }: { d: Twin }) {
  const [i, setI] = useState(
    d.fragments.findIndex((f) => f.fragment_id === d.selected_fragment_id),
  );
  const f = d.fragments[i < 0 ? 0 : i];
  return (
    <section className="twin">
      <div className="twin-head">
        <h1>Twin Inspector</h1>
        <p>{d.title}</p>
      </div>
      <aside className="fragment-index">
        {d.fragments.map((x, k) => (
          <button onClick={() => setI(k)} className={k === i ? 'selected' : ''} key={x.fragment_id}>
            <span className="fragment-code">{x.label}</span>
            <small>{x.semantic_label}</small>
          </button>
        ))}
      </aside>
      <div className="transition">
        <h2>{f.label}</h2>
        <p>
          {f.semantic_label} · {f.provenance.observation_status}
        </p>
        <div className="anatomy">
          {[f.precondition, f.typed_action, f.effect, f.evidence].map((x) => (
            <article key={x.label}>
              <small>{x.label}</small>
              <h3>{x.summary}</h3>
              <Hash v={x.digest} />
            </article>
          ))}
        </div>
        <h3>State delta</h3>
        <table>
          <tbody>
            {f.state_delta.map((x) => (
              <tr key={x.field}>
                <td>{x.field}</td>
                <td>{x.before}</td>
                <td>{x.after}</td>
                <td>{x.effect}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <aside className="evidence-rail">
        <h3>Runtime trace</h3>
        <Hash v={f.runtime_trace.trace_digest} />
        <h3>Oracle binding</h3>
        <Hash v={f.oracle_binding.binding_digest} />
        <p>{f.fidelity.determinism}</p>
      </aside>
    </section>
  );
}
function ReplayPage({ d }: { d: Replay }) {
  const [step, setStep] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [manifestStatus, setManifestStatus] = useState<
    'idle' | 'checking' | 'match' | 'mismatch' | 'unavailable'
  >('idle');
  useEffect(() => {
    if (!playing) return;
    const t = setInterval(() => setStep((x) => (x + 1) % 3), 700);
    return () => clearInterval(t);
  }, [playing]);
  const lanes = [d.vulnerable, d.patched];
  const current = d.vulnerable.steps[step];
  const verifyManifest = async () => {
    setManifestStatus('checking');
    try {
      const digest = await canonicalSha256(d.evidence_manifest);
      setManifestStatus(digest === d.hashes.evidence_hash ? 'match' : 'mismatch');
    } catch {
      setManifestStatus('unavailable');
    }
  };
  return (
    <section className="replay">
      <div className="replay-head">
        <div>
          <h1>{d.title}</h1>
          <Hash v={d.hashes.plan_hash} />
        </div>
        <div className="controls">
          <button onClick={() => setStep(0)}>Reset</button>
          <button onClick={() => setStep((x) => Math.max(0, x - 1))}>Prev</button>
          <button onClick={() => setPlaying((x) => !x)}>{playing ? 'Pause' : 'Play'}</button>
          <button onClick={() => setStep((x) => Math.min(2, x + 1))}>Next</button>
        </div>
      </div>
      <div className="lane-grid">
        <aside className="step-list">
          {d.vulnerable.steps.map((x, i) => (
            <button
              className={i === step ? 'selected' : ''}
              onClick={() => setStep(i)}
              key={x.sequence}
            >
              Step {String(x.sequence).padStart(2, '0')}
              <small>{x.label}</small>
            </button>
          ))}
        </aside>
        {lanes.map((l) => (
          <section className="lane" key={l.lane}>
            <h2>{l.lane}</h2>
            {l.steps.map((x, i) => (
              <article className={i === step ? 'selected' : ''} key={x.sequence}>
                <button className="lane-select" onClick={() => setStep(i)}>
                  <Mark v={x.verdict} />
                  {x.label}
                </button>
                <Hash v={x.evidence_digest} />
              </article>
            ))}
            <p>
              Terminal: <Mark v={l.terminal_verdict} />
              {l.terminal_verdict.replaceAll('_', ' ')}
            </p>
          </section>
        ))}
      </div>
      <aside className="replay-rail">
        <h2>Selected step</h2>
        <p>{current.label}</p>
        <p>{d.selected_observation.summary}</p>
        <Hash v={d.selected_observation.digest} />
        <h3>Evidence manifest</h3>
        {d.evidence_manifest.map((x) => (
          <p key={x.entry_id}>
            {x.label}
            <Hash v={x.digest} />
          </p>
        ))}
        <button disabled={manifestStatus === 'checking'} onClick={() => void verifyManifest()}>
          Verify fixture manifest
        </button>
        <p role="status">
          {manifestStatus === 'idle'
            ? 'Digest-only fixture; not materialized proof'
            : manifestStatus === 'checking'
              ? 'Computing canonical SHA-256…'
              : manifestStatus === 'match'
                ? 'Canonical manifest SHA-256 matches'
                : manifestStatus === 'mismatch'
                  ? 'Canonical manifest SHA-256 mismatch'
                  : 'Browser digest API unavailable'}
        </p>
        <p>{d.run_markers.map((x) => x.status).join(' · ')}</p>
        {d.controls.map((x) => (
          <p key={x.control_id}>
            {x.label}: {x.verdict}
          </p>
        ))}
      </aside>
    </section>
  );
}
export function App() {
  const [r, setR] = useState<Route>(route());
  const [o, setO] = useState<Overview>();
  const [w, setW] = useState<Worlds>();
  const [t, setT] = useState<Twin>();
  const [re, setRe] = useState<Replay>();
  const [e, setE] = useState<string>();
  useEffect(() => {
    const f = () => setR(route());
    addEventListener('popstate', f);
    return () => removeEventListener('popstate', f);
  }, []);
  useEffect(() => {
    Promise.all([
      get<Overview>('/v1/demo/overview'),
      get<Worlds>('/v1/demo/worlds'),
      get<Twin>('/v1/demo/twin'),
      get<Replay>('/v1/demo/replay'),
    ])
      .then(async ([a, b, c, d]) => {
        await assertFixtureBundle(a, b, c, d);
        setO(a);
        setW(b);
        setT(c);
        setRe(d);
      })
      .catch((x) => setE(x instanceof Error ? x.message : 'Fixture unavailable'));
  }, []);
  const go = (x: Route) => {
    history.pushState({}, '', path(x));
    setR(x);
  };
  return (
    <Shell r={r} set={go} p={o?.provenance}>
      {!o || !w || !t || !re ? (
        <Loading e={e} />
      ) : r === 'overview' ? (
        <OverviewPage d={o} set={go} />
      ) : r === 'worlds' ? (
        <WorldsPage d={w} />
      ) : r === 'twin' ? (
        <TwinPage d={t} />
      ) : (
        <ReplayPage d={re} />
      )}
    </Shell>
  );
}
