-- Claude-backed inference needs distinct audit terminology while retaining prior Gemini records.
ALTER TABLE language_inferences RENAME TO language_inferences_prior;

CREATE TABLE language_inferences (
    id INTEGER PRIMARY KEY,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    subject_person_id INTEGER REFERENCES people(id),
    category TEXT NOT NULL CHECK(category IN ('Chinese', 'Russian', 'Slavic-other', 'Korean', 'Japanese', 'Arabic', 'Hebrew', 'Hindi', 'English', 'Unknown')),
    method TEXT NOT NULL CHECK(method IN ('explicit-statement', 'unicode-script', 'language-detector', 'gemini', 'claude', 'combined')),
    confidence TEXT NOT NULL CHECK(confidence IN ('High', 'Medium', 'Low', 'Unknown')),
    detector_language TEXT,
    script_counts_json TEXT NOT NULL,
    rationale TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(finding_id)
);

INSERT INTO language_inferences (
    id, finding_id, subject_person_id, category, method, confidence,
    detector_language, script_counts_json, rationale, created_at
)
SELECT
    id, finding_id, subject_person_id, category, method, confidence,
    detector_language, script_counts_json, rationale, created_at
FROM language_inferences_prior;

DROP TABLE language_inferences_prior;
