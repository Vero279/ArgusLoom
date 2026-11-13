export default function ConfidenceBar({ value }: { value: number | null }) {
  if (value === null) {
    return (
      <section className="detail-section" aria-labelledby="confidence-heading">
        <h3 id="confidence-heading">Confiança das ligações</h3>
        <p className="muted-copy">Sem ligações para estimar a confiança.</p>
      </section>
    );
  }

  const percent = Math.round(Math.max(0, Math.min(1, value)) * 100);
  return (
    <section className="detail-section" aria-labelledby="confidence-heading">
      <div className="confidence-title">
        <h3 id="confidence-heading">Confiança das ligações</h3>
        <strong>{percent}%</strong>
      </div>
      <div
        className="confidence-track"
        role="meter"
        aria-label="Confiança média das ligações relacionadas"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percent}
      >
        <span style={{ width: `${percent}%` }} />
      </div>
      <p className="muted-copy">Média da confiança das relações ligadas a este nó.</p>
    </section>
  );
}
