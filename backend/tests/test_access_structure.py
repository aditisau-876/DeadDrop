from app.services.access_structure import evaluate
def test_threshold():
    p={"type":"THRESHOLD","threshold":2,"children":[{"type":"leaf","trustee_id":"T1"},{"type":"leaf","trustee_id":"T2"},{"type":"leaf","trustee_id":"T3"}]}
    assert evaluate(p,{"T1","T3"})
    assert not evaluate(p,{"T1"})
