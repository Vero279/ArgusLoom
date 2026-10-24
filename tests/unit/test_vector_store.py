from argusloom.rag.vector_store import VectorStore


def test_vector_store_add_and_count(tmp_path) -> None:
    store = VectorStore(tmp_path / "chroma", collection_name="unit-test")
    store.reset()

    embeddings = [[1.0, 0.0], [0.0, 1.0]]
    store.add(
        ["doc-1", "doc-2"],
        ["first text", "second text"],
        [{"kind": "a"}, {"kind": "b"}],
        embeddings,
    )

    assert store.count() == 2


def test_vector_store_query_returns_most_similar_document(tmp_path) -> None:
    store = VectorStore(tmp_path / "chroma", collection_name="unit-query")
    store.reset()

    embeddings = [[1.0, 0.0], [0.2, 0.9]]
    store.add(
        ["doc-1", "doc-2"],
        ["network ingress", "database encryption"],
        [{"kind": "network"}, {"kind": "data"}],
        embeddings,
    )

    hits = store.query([1.0, 0.0], top_k=1)

    assert hits
    assert hits[0].id == "doc-1"


def test_vector_store_reset_clears_collection(tmp_path) -> None:
    store = VectorStore(tmp_path / "chroma", collection_name="unit-reset")
    store.reset()
    store.add(["doc-1"], ["hello"], [{"kind": "note"}], [[1.0, 0.0]])

    assert store.count() == 1

    store.reset()

    assert store.count() == 0
