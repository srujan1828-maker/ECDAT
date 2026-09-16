import {
  EnvironmentEvidence as EnvironmentData,
  PQEvidence as PQData,
} from "@/lib/api";

export function EnvironmentEvidence({
  environment,
}: {
  environment?: EnvironmentData;
}) {
  return (
    <section
      className="discovery-evidence"
      aria-label="Automatically discovered environment"
    >
      <h3>Automatically discovered environment</h3>
      <p className="field-help">
        The scan checks public headers and a bounded HTML sample. Linked
        dependency manifests add stack and database clues when you build the
        plan.
      </p>
      {environment?.signals?.length ? (
        <div className="table-scroll">
          <table className="discovery-table">
            <thead>
              <tr>
                <th>Category</th>
                <th>Detected hint</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {environment.signals.map((s, i) => (
                <tr key={i}>
                  <td>{s.category}</td>
                  <td>
                    <strong>{s.value}</strong>
                    <small>{s.confidence.replaceAll("_", " ")}</small>
                  </td>
                  <td>
                    {s.evidence}
                    <small>{s.source}</small>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="field-help">
          {environment
            ? "No reliable public technology markers were found. You can still generate a plan with unknowns clearly listed."
            : "Inspect a website to discover its environment. For older saved scans, run a new inspection."}
        </p>
      )}
      <p className="field-help">
        Edge/CDN clues do not prove the origin provider, region, database, or
        deployment method. Hidden details are left unknown.
      </p>
    </section>
  );
}
export function PostQuantumEvidence({ evidence }: { evidence?: PQData }) {
  return (
    <section
      className="discovery-evidence"
      aria-label="Post-quantum probe evidence"
    >
      <h3>Post-quantum key-exchange tests</h3>
      {!evidence ? (
        <p className="field-help">
          This saved scan predates PQ measurements. Run a new website scan.
        </p>
      ) : (
        <>
          <p className="field-help">{evidence.reason}</p>
          <div className="table-scroll">
            <table className="discovery-table">
              <thead>
                <tr>
                  <th>Offered TLS group</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {evidence.tests.map((t) => (
                  <tr key={t.group}>
                    <td>{t.group}</td>
                    <td>
                      <strong>
                        {(
                          {
                            negotiated: "Handshake verified",
                            not_negotiated: "Did not negotiate",
                            scanner_unavailable: "Scanner cannot test",
                            inconclusive: "Inconclusive",
                          } as Record<string, string>
                        )[t.status] || t.status}
                      </strong>
                      <small>{t.reason || t.evidence}</small>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="field-help">
            {evidence.scanner_version} · {evidence.scope}
          </p>
          <p className="field-help">
            A verified hybrid exchange protects key establishment. It does not
            prove post-quantum certificate signatures or application-wide
            safety.
          </p>
        </>
      )}
    </section>
  );
}
