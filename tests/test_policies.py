from qid.policies import evaluate_policy_placeholder


def test_policy_placeholder_allows() -> None:
    out = evaluate_policy_placeholder({"service_id": "example.com", "level": 2})
    assert out["decision"] == "allow"
    assert "placeholder" in out["reason"]
