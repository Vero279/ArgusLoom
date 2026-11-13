import cvesJson from '../../../data/fixtures/cves.json';
import attackJson from '../../../data/mitre/attack.json';
import atlasJson from '../../../data/mitre/atlas.json';
import type { CVERecord, TechniqueRecord } from '../api';

export const cveRecords = cvesJson as CVERecord[];
export const attackTechniques = attackJson as TechniqueRecord[];
export const atlasTechniques = atlasJson as TechniqueRecord[];

export const cveById = new Map(cveRecords.map((record) => [record.id, record]));
export const techniqueById = new Map(
  [...attackTechniques, ...atlasTechniques].map((record) => [record.id, record]),
);
