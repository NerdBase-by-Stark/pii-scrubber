from piiscrub.detectors import build_active
from piiscrub.engine import AliasMap, reverse_text, tokenize


def test_consistent_alias_across_files():
    dets = build_active()
    amap = AliasMap()
    t1, _ = tokenize("ip 10.0.0.5 here", dets, amap, file="a.log")
    t2, _ = tokenize("again 10.0.0.5 there", dets, amap, file="b.log")
    assert "<IP_1>" in t1 and "<IP_1>" in t2
    # one unique IP value, seen in two files
    entry = amap.decode_table()["<IP_1>"]
    assert entry["count"] == 2
    assert set(entry["files"]) == {"a.log", "b.log"}


def test_url_outranks_host_and_ip():
    dets = build_active()
    amap = AliasMap()
    out, reps = tokenize("see https://host.corp/x?ip=1.2.3.4 ok", dets, amap)
    assert {r.category for r in reps} == {"url"}
    assert out.count("<URL_1>") == 1
    assert "host.corp" not in out and "1.2.3.4" not in out


def test_reverse_roundtrip():
    dets = build_active()
    amap = AliasMap()
    src = "mail a@b.com from 10.1.2.3 mac de:ad:be:ef:00:11"
    out, _ = tokenize(src, dets, amap)
    assert reverse_text(out, amap.reverse_pairs()) == src


def test_winuser_capture_group_keeps_prefix():
    dets = build_active()
    amap = AliasMap()
    out, reps = tokenize(r"path C:\Users\jdoe\app\run.log done", dets, amap)
    assert out == r"path C:\Users\<WINUSER_1>\app\run.log done"
    assert reps[0].category == "windows_user_path"


def test_credit_card_luhn_accept_and_reject():
    dets = build_active()
    a1 = AliasMap()
    _, reps_ok = tokenize("card 4111 1111 1111 1111 end", dets, a1)
    assert any(r.category == "credit_card" for r in reps_ok)
    a2 = AliasMap()
    _, reps_bad = tokenize("num 1234 5678 9012 3456 zz", dets, a2)
    assert not any(r.category == "credit_card" for r in reps_bad)


def test_email_casefold_shares_alias():
    dets = build_active()
    amap = AliasMap()
    out, _ = tokenize("A@Example.com and a@example.COM", dets, amap)
    aliases = [a for a, m in amap.decode_table().items() if m["category"] == "email"]
    assert len(aliases) == 1
