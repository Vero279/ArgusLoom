from argusloom.rag.embeddings import EmbeddingModel


def test_embedding_model_dimension_is_positive() -> None:
    model = EmbeddingModel(model_name="all-MiniLM-L6-v2")

    vector = model.embed_one("network exposure")

    assert len(vector) > 0


def test_embedding_model_similarity_for_similar_texts() -> None:
    model = EmbeddingModel(model_name="all-MiniLM-L6-v2")

    a = model.embed_one("public ingress and tls hardening")
    b = model.embed_one("public ingress with tls controls")
    c = model.embed_one("database checksum and encryption")

    sim_ab = model.cosine_similarity(a, b)
    sim_ac = model.cosine_similarity(a, c)

    assert sim_ab > 0.7
    assert sim_ac < 0.5
