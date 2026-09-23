CREATE VIRTUAL TABLE repository_search USING fts5(
    repository_id UNINDEXED,
    identity_key,
    canonical_url,
    purpose,
    tool_types,
    capabilities,
    intended_uses,
    documented_people,
    tokenize = 'unicode61 remove_diacritics 2'
);
