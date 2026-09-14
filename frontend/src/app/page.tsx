'use client';

import { useCallback, useEffect, useState } from 'react';
import { Activity, Binary, Code2, Download, Globe, ShieldCheck, RefreshCw } from 'lucide-react';
import { requestApi, Scan, ScanResult } from '@/lib/api';

const inputClass = 'w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-slate-100 outline-none focus:border-cyan-400';
const buttonClass = 'rounded-xl bg-cyan-300 px-5 py-3 text-sm font-semibold text-slate-950 hover:bg-cyan-200 disabled:opacity-40 disabled:cursor-not-allowed';
const languageExtensions: Record<string, string> = { python: 'py', java: 'java', c_cpp: 'cpp', golang: 'go', javascript: 'js' };

export default function Dashboard() {
  const [projectInput, setProjectInput] = useState('default');
  const [project, setProject] = useState('default');
  const [token, setToken] = useState('');
  const [mode, setMode] = useState<'network' | 'code' | 'binary'>('network');
  const [target, setTarget] = useState('');
  const [language, setLanguage] = useState('python');
  const [code, setCode] = useState('');
  const [sourceFiles, setSourceFiles] = useState<File[]>([]);
  const [binary, setBinary] = useState<File | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [connected, setConnected] = useState(false);
  const [exportIds, setExportIds] = useState<string[]>([]);

  const refresh = useCallback(async () => {
    try {
      const records = await requestApi<Scan[]>('/scans', project, token);
      setScans(records);
      setConnected(true);
    } catch (err) {
      setConnected(false);
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [project, token]);

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    const update = async () => {
      try {
        const records = await requestApi<Scan[]>('/scans', project, token);
        if (active) { setScans(records); setConnected(true); }
      } catch (err) {
        if (active) { setConnected(false); setError(err instanceof Error ? err.message : String(err)); }
      } finally {
        if (active) timer = setTimeout(() => void update(), 2500);
      }
    };
    void update();
    return () => { active = false; clearTimeout(timer); };
  }, [project, token]);

  async function submit() {
    setBusy(true); setError('');
    try {
      let path: string;
      let body: unknown;
      if (mode === 'network') {
        if (!target.trim()) throw new Error('Enter a hostname or HTTPS URL.');
        path = '/scan/network'; body = { target: target.trim() };
      } else if (mode === 'binary') {
        if (!binary) throw new Error('Choose a binary or ZIP file.');
        if (binary.size === 0 || binary.size > 8 * 1024 * 1024) throw new Error('Upload must contain 1 byte to 8 MiB.');
        path = '/scan/binary/upload';
        const form = new FormData(); form.append('file', binary); body = form;
      } else {
        path = '/scan/sources';
        if (sourceFiles.length > 100 || sourceFiles.reduce((sum, f) => sum + f.size, 0) > 8 * 1024 * 1024) throw new Error('Choose at most 100 source files totaling 8 MiB.');
        const files = sourceFiles.length ? await Promise.all(sourceFiles.map(async file => ({ path: file.webkitRelativePath || file.name, content: await file.text() })))
          : [{ path: `snippet.${languageExtensions[language]}`, content: code, language }];
        if (!sourceFiles.length && !code.trim()) throw new Error('Paste code or choose source files.');
        body = { files };
      }
      const scan = await requestApi<Scan>(path, project, token, body);
      setSelected(scan.id); await refresh();
    } catch (err) { setError(err instanceof Error ? err.message : String(err)); }
    finally { setBusy(false); }
  }

  async function cancel(id: string) {
    try { await requestApi(`/scans/${id}/cancel`, project, token, {}); await refresh(); }
    catch (err) { setError(err instanceof Error ? err.message : String(err)); }
  }

  async function download() {
    setError('');
    try {
      const data = await requestApi('/export/cbom', project, token, { scan_ids: exportIds, target_name: project });
      const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
      const link = document.createElement('a'); link.href = url; link.download = `${project}-cbom.json`; link.click(); URL.revokeObjectURL(url);
    } catch (err) { setError(err instanceof Error ? err.message : String(err)); }
  }

  const current = scans.find(s => s.id === selected);
  const result: ScanResult | null = current?.result || null;
  const findings = result?.findings || result?.detections || [];
  const completed = scans.filter(s => s.status === 'completed');
  const running = scans.filter(s => ['queued', 'running'].includes(s.status));

  return <main className="min-h-screen bg-slate-950 text-slate-100">
    <header className="border-b border-slate-800 px-6 py-5 lg:px-10 flex items-center justify-between gap-4">
      <div className="flex items-center gap-3"><ShieldCheck className="text-cyan-300" size={30} /><div><h1 className="text-xl font-bold tracking-tight">ECDAT</h1><p className="text-xs text-slate-400">Cryptographic discovery & evidence</p></div></div>
      <span className={`text-xs ${connected ? 'text-emerald-300' : 'text-amber-300'}`}>{connected ? 'Backend connected' : 'Backend unavailable'}</span>
    </header>
    <div className="mx-auto max-w-7xl px-6 py-8 lg:px-10 space-y-7">
      <div className="flex flex-wrap justify-between items-end gap-5"><div><p className="text-xs uppercase tracking-widest text-cyan-300 mb-2">Scan workspace</p><h2 className="text-3xl font-semibold">Know what your systems use.</h2><p className="mt-2 text-sm text-slate-400">Run measured scans, inspect coverage, and export selected evidence.</p></div>
        <div className="flex gap-2 items-end"><label className="text-xs text-slate-400">Project<input aria-label="Project" className={inputClass} value={projectInput} onChange={e => setProjectInput(e.target.value)} /></label><button className={buttonClass} disabled={busy} onClick={() => { if (!/^[A-Za-z0-9_-]{1,64}$/.test(projectInput)) { setError('Use 1–64 letters, numbers, underscores or hyphens for project.'); return; } setProject(projectInput); setScans([]); setSelected(null); setExportIds([]); setError(''); }}>Open</button></div>
      </div>
      <details className="text-sm text-slate-400"><summary className="cursor-pointer">Backend access token</summary><input type="password" autoComplete="off" aria-label="Backend access token" placeholder="Required only when the backend has a token configured" className={`${inputClass} mt-3 max-w-xl`} value={token} onChange={e => { setToken(e.target.value); setError(''); }} /><p className="text-xs mt-2">Kept in memory for this page. Project names organize scans; access is shared by token.</p></details>
      {error && <div role="alert" className="rounded-xl border border-red-800 bg-red-950/40 p-4 text-sm text-red-200 flex justify-between gap-4"><span>{error}</span><button onClick={() => setError('')} aria-label="Dismiss error">Dismiss</button></div>}
      <div className="grid grid-cols-3 gap-4">{[['Completed scans', completed.length], ['Queued / running', running.length], ['Selected for export', exportIds.length]].map(([label, count]) => <div key={label} className="rounded-2xl border border-slate-800 bg-slate-900/50 p-5"><p className="text-xs text-slate-400">{label}</p><p className="mt-2 text-2xl font-semibold">{count}</p></div>)}</div>
      <section className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5 sm:p-7">
        <div className="flex flex-wrap gap-2 mb-6">{([{ id: 'network', label: 'Network / TLS', Icon: Globe }, { id: 'code', label: 'Source files', Icon: Code2 }, { id: 'binary', label: 'Binary / firmware', Icon: Binary }] as const).map(({ id, label, Icon }) => <button key={id} onClick={() => setMode(id)} aria-pressed={mode === id} className={`flex items-center gap-2 rounded-xl px-4 py-3 text-sm ${mode === id ? 'bg-cyan-300 text-slate-950' : 'bg-slate-800 text-slate-300'}`}><Icon size={16} />{label}</button>)}</div>
        {mode === 'network' && <div className="space-y-3"><label className="text-sm">Hostname or URL<input className={`${inputClass} mt-2`} placeholder="example.org or https://example.org:8443" value={target} onChange={e => setTarget(e.target.value)} /></label><p className="text-xs text-slate-400">Checks a bounded set of TLS versions and ciphers plus certificate trust. PQC status stays unknown unless measured. Scan only authorized targets.</p></div>}
        {mode === 'code' && <div className="space-y-4"><div className="flex flex-wrap gap-4 items-center"><select aria-label="Snippet language" className={`${inputClass} max-w-48`} value={language} onChange={e => setLanguage(e.target.value)}>{Object.keys(languageExtensions).map(lang => <option key={lang}>{lang}</option>)}</select><label className="text-sm text-slate-300">Source files<input type="file" multiple aria-label="Source files" className="block mt-2 text-xs" onChange={e => setSourceFiles(Array.from(e.target.files || []))} /></label><label className="text-sm text-slate-300">Source folder<input type="file" multiple {...{ webkitdirectory: '' }} aria-label="Source folder" className="block mt-2 text-xs" onChange={e => setSourceFiles(Array.from(e.target.files || []))} /></label></div>
          {sourceFiles.length ? <p className="text-sm text-cyan-200">{sourceFiles.length} files selected. <button className="underline" onClick={() => setSourceFiles([])}>Use pasted code instead</button></p> : <textarea aria-label="Source code" rows={9} className={`${inputClass} font-mono`} placeholder="Paste source code here…" value={code} onChange={e => setCode(e.target.value)} />}
          <p className="text-xs text-slate-400">Python AST with common aliases and constants; other languages use heuristic rules. Up to 100 files / 8 MiB. Unsupported files and parse errors appear in coverage.</p></div>}
        {mode === 'binary' && <div className="rounded-xl border border-dashed border-slate-600 p-8"><label className="block text-sm">Choose a binary, firmware image, or ZIP<input type="file" aria-label="Binary file" className="block mt-4 text-sm" onChange={e => setBinary(e.target.files?.[0] || null)} /></label><p className="mt-4 text-xs text-slate-400">Maximum 8 MiB; ZIP expansion is limited to 100 entries / 8 MiB and one level. Signatures indicate presence, not execution.</p></div>}
        <button className={`${buttonClass} mt-5`} disabled={busy || !connected} onClick={() => void submit()}>{busy ? 'Submitting…' : 'Start scan'}</button>
      </section>
      <div className="grid lg:grid-cols-[0.85fr_1.4fr] gap-6">
        <section className="rounded-2xl border border-slate-800 p-5 min-w-0"><div className="flex items-center justify-between mb-4"><h3 className="font-semibold flex gap-2 items-center"><Activity size={18} />Scan history</h3><button aria-label="Refresh scans" onClick={() => void refresh()}><RefreshCw size={16} /></button></div>
          <p className="text-xs text-slate-400 mb-4">Latest 200 scans in {project}. Select completed scans for export.</p>
          {!scans.length && <p className="py-10 text-sm text-slate-500">No scans yet. Start with your own target or file.</p>}
          <div className="space-y-2 max-h-[620px] overflow-y-auto">{scans.map(scan => <div key={scan.id} className={`rounded-xl border p-3 ${selected === scan.id ? 'border-cyan-500 bg-cyan-950/30' : 'border-slate-800'}`}><div className="flex gap-3 items-center"><input type="checkbox" aria-label={`Export scan ${scan.id}`} disabled={scan.status !== 'completed'} checked={exportIds.includes(scan.id)} onChange={e => setExportIds(ids => e.target.checked ? [...ids, scan.id] : ids.filter(id => id !== scan.id))} /><button className="text-left flex-1" onClick={() => setSelected(scan.id)}><span className="text-sm capitalize">{scan.kind} · {scan.id.slice(0, 8)}</span><span className="block text-xs text-slate-400 mt-1">{new Date(scan.created_at).toLocaleString()}</span></button><span className={`text-xs ${scan.status === 'failed' ? 'text-red-300' : 'text-cyan-200'}`}>{scan.status}</span></div>{['queued', 'running'].includes(scan.status) && <button className="mt-2 text-xs text-slate-400 underline" onClick={() => void cancel(scan.id)}>Cancel result collection</button>}</div>)}</div>
          <button className={`${buttonClass} mt-5 flex items-center gap-2`} disabled={!exportIds.length} onClick={() => void download()}><Download size={16} />Export CBOM</button>
        </section>
        <section className="rounded-2xl border border-slate-800 p-5 min-w-0"><h3 className="font-semibold mb-4">Evidence & coverage</h3>
          {!current ? <p className="text-sm text-slate-500 py-10">Select a scan to inspect its evidence.</p> : <div className="space-y-5"><p className="text-xs text-slate-400 break-all">Scan {current.id}<br />Engine {current.engine_version}<br />Input SHA-256: {current.input_hash}</p>
            {current.error && <p role="alert" className="text-sm text-red-300">{current.error}</p>}
            {current.status === 'cancelled' && <p className="text-sm text-slate-400">Result collection cancelled. An in-progress bounded operation may finish in the background.</p>}
            {['running', 'queued'].includes(current.status) && <p role="status" className="text-sm text-cyan-300">{current.status === 'running' ? 'Analyzing your input…' : 'Waiting for a worker…'}</p>}
            {result && <><p className="text-sm text-slate-300">{current.kind === 'network' ? `${result.target} · ${result.protocol} · ${result.cipher_name}` : `${findings.length} indicators found. Zero indicators does not establish cryptographic safety.`}</p>
              {result.status === 'partial' && <p className="text-sm text-amber-300">Partial coverage: inspect skipped files and errors below.</p>}
              {findings.map((finding, index) => <article key={index} className="rounded-xl bg-slate-900 p-4"><div className="flex justify-between gap-3"><h4 className="text-sm font-medium">{finding.primitive}</h4><span className="text-xs text-amber-200">{finding.severity}</span></div><p className="text-xs text-cyan-200 mt-2 break-all">{finding.file} {finding.line ? `: ${finding.line}` : finding.offset}</p><p className="text-sm text-slate-400 mt-2">{finding.issue || finding.description}</p><p className="text-xs text-slate-500 mt-2">Confidence: {finding.confidence || 'unassessed'} {finding.engine}</p></article>)}
              <details open><summary className="text-sm text-slate-300 cursor-pointer">Coverage and measured details</summary><pre className="mt-3 p-4 rounded-xl bg-slate-900 text-xs text-slate-400 whitespace-pre-wrap break-all max-h-96 overflow-auto">{JSON.stringify({ coverage: result.coverage, certificate: result.certificate, pqc_status: result.pqc_status, protocol_tests: result.protocol_tests, cipher_tests: result.cipher_tests, dependencies: result.dependencies, members: result.members, limitations: result.limitations }, null, 2)}</pre></details>
            </>}
          </div>}
        </section>
      </div>
    </div>
  </main>;
}
