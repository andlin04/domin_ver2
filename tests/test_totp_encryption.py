"""Two-factor secrets encrypted at rest (domin.secretbox): round trip, migration of plaintext values, missing or wrong
key failing closed, re-keying. Test secrets are throwaway values; the key is the run's temporary one (conftest)."""
import json
import logging
import time
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from domin import __main__ as cli
from domin import admin, db, secretbox, totp, users
from domin.config import Settings
from domin.web import create_app

PW = "correct horse battery"
SECRET = "JBSWY3DPEHPK3PXP"   # the well-known example secret, never a real one


@pytest.fixture
def settings(tmp_path):
    s = replace(Settings.from_env(), db_path=tmp_path / "t.db", admin_ips=())
    db.init(s.db_path)
    return s


def now_code(secret):
    return totp._code(secret, int(time.time() // totp.STEP))


def stored(settings, name):
    with db.connect(settings.db_path) as c:
        return c.execute("SELECT totp_secret FROM users WHERE name = ?", (name,)).fetchone()[0]


def plaintext_user(settings, name="tia", secret=SECRET):
    """A user as an older release stored it: the secret in plaintext."""
    with db.connect(settings.db_path) as c:
        uid = users.create(c, name, "admin", PW)
        c.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, uid))
    return uid


def other_key(tmp_path, name="other.key"):
    path = tmp_path / name
    secretbox.write_key(path, secretbox.new_key())
    return path


def test_round_trip_and_prefix():
    value = secretbox.encrypt(SECRET)
    assert value.startswith("f1:") and SECRET not in value
    assert secretbox.decrypt(value) == SECRET
    assert secretbox.encrypt(SECRET) != value   # random IV: never the same ciphertext twice
    assert secretbox.decrypt(SECRET) == SECRET   # no prefix: a plaintext value from before


def test_enrolment_stores_only_ciphertext(settings):
    with db.connect(settings.db_path) as c:
        uid = users.create(c, "tia", "admin", PW)
        secret, codes = users.start_enrol(c, uid)
        raw = admin.kv_get(c, f"enrol:{uid}")
        assert raw.startswith("f1:") and secret not in raw and not any(x in raw for x in codes)
        assert users.enrol_pending(c, uid) == {"secret": secret, "recovery": codes}
        assert users.confirm_enrol(c, uid, now_code(secret)) == codes
        row = c.execute("SELECT totp_secret, recovery FROM users WHERE id = ?", (uid,)).fetchone()
    assert row[0].startswith("f1:") and row[0] != secret and secret not in row[0]
    assert json.loads(row[1]) == [totp.hash_recovery(x) for x in codes]   # hashes, not the codes
    assert not any(x in row[1] for x in codes)


def test_plaintext_is_migrated_at_start_and_still_verifies(settings):
    uid = plaintext_user(settings)
    with db.connect(settings.db_path) as c:
        admin.kv_set(c, f"enrol:{uid}", json.dumps({"secret": SECRET, "recovery": ["aaaa-bbbb-cccc"]}))
    db.init(settings.db_path)
    value = stored(settings, "tia")
    assert value.startswith("f1:") and value != SECRET
    with db.connect(settings.db_path) as c:
        assert admin.kv_get(c, f"enrol:{uid}").startswith("f1:")
        assert users.enrol_pending(c, uid)["secret"] == SECRET
        assert users.verify_second_factor(c, uid, now_code(SECRET))


def test_migration_is_idempotent(settings):
    plaintext_user(settings)
    with db.connect(settings.db_path) as c:
        assert users.migrate_totp_encryption(c) == 1
        assert users.migrate_totp_encryption(c) == 0
    first = stored(settings, "tia")
    db.init(settings.db_path)
    assert stored(settings, "tia") == first


def test_migration_waits_for_a_missing_key(settings, monkeypatch, tmp_path, caplog):
    monkeypatch.setenv("DOMIN_TOTP_KEY", str(tmp_path / "absent.key"))
    plaintext_user(settings)
    with caplog.at_level(logging.WARNING):
        db.init(settings.db_path)   # no crash
    assert stored(settings, "tia") == SECRET and "stay unencrypted" in caplog.text


@pytest.mark.parametrize("bad", ["missing", "wrong", "garbage"])
def test_missing_or_wrong_key_fails_closed(settings, monkeypatch, tmp_path, caplog, bad):
    with db.connect(settings.db_path) as c:
        uid = users.create(c, "tia", "admin", PW)
        secret, codes = users.start_enrol(c, uid)
        users.confirm_enrol(c, uid, now_code(secret))
        c.execute("UPDATE users SET totp_last_step = -1 WHERE id = ?", (uid,))
    path = {"missing": tmp_path / "absent.key", "wrong": other_key(tmp_path), "garbage": tmp_path / "bad.key"}[bad]
    if bad == "garbage":
        path.write_text("not a key")
    monkeypatch.setenv("DOMIN_TOTP_KEY", str(path))
    db.init(settings.db_path)   # the app still starts
    with db.connect(settings.db_path) as c, caplog.at_level(logging.ERROR):
        with pytest.raises(users.KeyUnavailable):
            users.verify_second_factor(c, uid, now_code(secret))
        assert "2FA unavailable for user tia" in caplog.text
        assert users.verify_second_factor(c, uid, codes[0])   # recovery codes are hashes: still accepted
        if bad != "wrong":   # a wrong but valid key can still start a new enrolment (encrypted with it)
            with pytest.raises(users.KeyUnavailable):
                users.start_enrol(c, uid)
        users.disable_totp(c, uid)   # the admin reset needs no key
        assert not users.get(c, uid)["has_totp"]


def test_sign_in_says_2fa_unavailable(settings, monkeypatch, tmp_path):
    with db.connect(settings.db_path) as c:
        uid = users.create(c, "tia", "admin", PW)
        secret, _ = users.start_enrol(c, uid)
        users.confirm_enrol(c, uid, now_code(secret))
        c.execute("UPDATE users SET totp_last_step = -1 WHERE id = ?", (uid,))
    monkeypatch.setenv("DOMIN_TOTP_KEY", str(tmp_path / "absent.key"))
    with TestClient(create_app(settings), base_url="https://testserver", client=("203.0.113.9", 50000)) as h:
        r = h.post("/admin/login", data={"name": "tia", "password": PW})
        assert r.status_code == 200
        r = h.post("/admin/login/totp", data={"code": now_code(secret)}, follow_redirects=False)
    assert r.status_code == 503 and "2FA unavailable, contact an admin" in r.text


def test_break_glass_admin_password_without_key(settings, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("DOMIN_DB", str(settings.db_path))
    monkeypatch.setenv("DOMIN_TOTP_KEY", str(tmp_path / "absent.key"))
    with db.connect(settings.db_path) as c:
        users.create(c, "admin", "admin", PW)
    monkeypatch.setattr(cli.sys, "stdin", type("S", (), {"isatty": lambda self: False,
                                                         "readline": lambda self: "another long password\n"})())
    assert cli.main(["admin-password"]) == 0
    with db.connect(settings.db_path) as c:
        assert users.verify_password(c, "admin", "another long password")


def test_rekey(settings, monkeypatch, tmp_path, totp_key, capsys):
    monkeypatch.setenv("DOMIN_DB", str(settings.db_path))
    with db.connect(settings.db_path) as c:
        uid = users.create(c, "tia", "admin", PW)
        secret, _ = users.start_enrol(c, uid)
        users.confirm_enrol(c, uid, now_code(secret))
        c.execute("UPDATE users SET totp_last_step = -1 WHERE id = ?", (uid,))
        pid = users.create(c, "pia", "power", PW)
        users.start_enrol(c, pid)   # a pending enrolment is re-keyed too
    before = stored(settings, "tia")
    new = tmp_path / "new.key"
    assert cli.main(["totp-rekey", "--new-key", str(new)]) == 0   # creates the new key file
    assert "2 values re-encrypted" in capsys.readouterr().out
    after = stored(settings, "tia")
    assert after.startswith("f1:") and after != before and secret not in after
    with db.connect(settings.db_path) as c:
        assert users.enrol_pending(c, pid) is None   # the old key no longer decrypts
        with pytest.raises(secretbox.KeyUnavailable):
            secretbox.decrypt(after)
        monkeypatch.setenv("DOMIN_TOTP_KEY", str(new))
        assert users.enrol_pending(c, pid)["secret"]
        assert users.verify_second_factor(c, uid, now_code(secret))
    # --old-key: back to the first key; a wrong old key changes nothing
    assert cli.main(["totp-rekey", "--new-key", str(totp_key), "--old-key", str(other_key(tmp_path))]) == 1
    assert stored(settings, "tia") == after
    assert cli.main(["totp-rekey", "--new-key", str(totp_key), "--old-key", str(new)]) == 0
    monkeypatch.setenv("DOMIN_TOTP_KEY", str(totp_key))
    assert secretbox.decrypt(stored(settings, "tia")) == secret
