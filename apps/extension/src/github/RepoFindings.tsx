// The deterministic part of the repo badge: what the repo does, per-file findings, and the
// dependency scan. Pure presentation of a RepoResult — no requests, no state.

import type { RepoResult } from '../lite/repo';
import { BlockHeader, CopyButton } from '../ui/primitives';
import { panel, sectionLabel, SEV_COLOR, VERDICT_COLOR } from '../ui/theme';

export function RepoFindings({ result }: { result: RepoResult }) {
    const selfFindings = result.self?.findings ?? [];
    const what = result.self?.what ?? [];

    const whatCopy = `Kotiq — ${result.repo} (${result.worst})\nWhat this repo does:\n${what.map((w) => '• ' + w).join('\n')}`;
    const filesCopy = `Kotiq — ${result.repo} (${result.worst})\n${selfFindings
        .map((f) => `[${f.severity}] ${f.file} — ${f.label}${f.detail ? '\n    ' + f.detail : ''}`)
        .join('\n')}`;

    return (
        <>
            {what.length > 0 && (
                <div style={{ ...panel, background: '#fff8f8' }}>
                    <BlockHeader
                        title={<span style={{ color: VERDICT_COLOR.MALICIOUS, fontWeight: 700 }}>⚠ What this repo does</span>}
                        actions={<CopyButton text={whatCopy} />}
                    />
                    {what.map((w, i) => (
                        <div key={i} style={{ fontSize: 12, color: '#3d2222', marginBottom: 5, lineHeight: 1.35 }}>• {w}</div>
                    ))}
                </div>
            )}

            {selfFindings.length > 0 && (
                <div style={panel}>
                    <BlockHeader
                        title={<span style={sectionLabel}>Repo files</span>}
                        actions={<CopyButton text={filesCopy} />}
                    />
                    {selfFindings.map((f, i) => (
                        <div key={i} style={{ marginBottom: 7 }}>
                            <span style={{ fontWeight: 700, color: SEV_COLOR[f.severity] ?? '#6e7781', fontSize: 11 }}>{f.severity}</span>{' '}
                            <code style={{ fontSize: 11, color: '#57606a' }}>{f.file}</code>
                            <div style={{ fontSize: 12, color: '#24292f', marginTop: 1 }}>{f.label}</div>
                            {f.detail && <div style={{ fontSize: 11, color: '#8a929b', marginTop: 1, fontFamily: 'ui-monospace, monospace', wordBreak: 'break-all' }}>{f.detail}</div>}
                        </div>
                    ))}
                </div>
            )}

            <div style={{ ...panel, color: '#57606a' }}>
                <div style={sectionLabel}>Dependency scan · {result.repo}</div>
                <b>{result.totalDeps}</b> dependencies · <b>{result.withHooks}</b> run install hooks
                {result.scanned < result.totalDeps && <> · scanned {result.scanned}</>}
            </div>

            {result.flagged.length ? (
                <div style={panel}>
                    <div style={{ color: VERDICT_COLOR.SUSPICIOUS, fontWeight: 600, marginBottom: 6 }}>⚠ Risky dependencies</div>
                    {result.flagged.slice(0, 8).map((d) => (
                        <div key={d.name} style={{ marginBottom: 6 }}>
                            <span style={{ fontWeight: 600, color: VERDICT_COLOR[d.verdict] }}>{d.verdict}</span>{' '}
                            <code>{d.name}@{d.version}</code>
                            <div style={{ fontSize: 12, color: '#57606a', marginTop: 1 }}>{d.findings.map((f) => f.label).join('; ')}</div>
                        </div>
                    ))}
                </div>
            ) : (
                <div style={{ ...panel, color: '#1a7f37' }}>No dependency runs a risky install hook.</div>
            )}

            <div style={{ padding: '10px 12px', color: '#8a929b', fontSize: 11 }}>
                Scanned on Kotiq's server, passively — the repo's own scripts, .vscode tasks, source &amp; .env, plus each dependency's install hooks. Nothing is executed.
            </div>
        </>
    );
}
