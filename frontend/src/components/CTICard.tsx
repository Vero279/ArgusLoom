import type { CVERecord, TechniqueRecord } from '../api';
import { severityForCvss, techniqueUrl } from '../security';

interface CVECardProps {
  type: 'cve';
  record: CVERecord;
}

interface TechniqueCardProps {
  type: 'attack' | 'atlas';
  record: TechniqueRecord;
}

export default function CTICard(props: CVECardProps | TechniqueCardProps) {
  if (props.type === 'cve') {
    const severity = props.record.severity || severityForCvss(props.record.cvss_score);
    return (
      <article className="cti-card">
        <div className="cti-card-heading">
          <a className="mono-link" href={`https://nvd.nist.gov/vuln/detail/${props.record.id}`} target="_blank" rel="noreferrer">
            {props.record.id}
          </a>
          <span className={`severity-chip severity-${severity.toLowerCase()}`}>{severity}</span>
        </div>
        <p>{props.record.description}</p>
        <span className="cvss-score">CVSS {props.record.cvss_score.toFixed(1)}</span>
      </article>
    );
  }

  const atlas = props.type === 'atlas';
  return (
    <article className="cti-card">
      <div className="cti-card-heading">
        <a className="mono-link" href={techniqueUrl(props.record, atlas)} target="_blank" rel="noreferrer">
          {props.record.id}
        </a>
        <span className={`framework-chip ${atlas ? 'atlas-chip' : ''}`}>{atlas ? 'ATLAS' : 'ATT&CK'}</span>
      </div>
      <h4>{props.record.name}</h4>
      <p className="technique-tactic">{props.record.tactic}</p>
      {props.record.description && <p>{props.record.description}</p>}
    </article>
  );
}
