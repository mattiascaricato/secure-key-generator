import hashlib
from unittest.mock import patch

import pytest

import generate_key


class TestIsValidPrivateKey:
    def test_zero_is_invalid(self):
        assert not generate_key.is_valid_private_key(bytes(32))

    def test_one_is_valid(self):
        assert generate_key.is_valid_private_key(bytes(31) + b"\x01")

    def test_order_minus_one_is_valid(self):
        key = (generate_key.SECP256K1_ORDER - 1).to_bytes(32, "big")
        assert generate_key.is_valid_private_key(key)

    def test_order_is_invalid(self):
        key = generate_key.SECP256K1_ORDER.to_bytes(32, "big")
        assert not generate_key.is_valid_private_key(key)

    def test_max_value_is_invalid(self):
        assert not generate_key.is_valid_private_key(b"\xff" * 32)


class TestMixEntropy:
    def test_xor_against_known_local_bytes(self):
        user = bytes(range(32))
        local = b"\xaa" * 32
        with patch.object(generate_key.secrets, "token_bytes", return_value=local):
            mixed = generate_key.mix_entropy(user)
        assert mixed == bytes(b ^ 0xAA for b in range(32))

    def test_returns_32_bytes(self):
        assert len(generate_key.mix_entropy(bytes(32))) == 32

    def test_fresh_local_bytes_change_result(self):
        user = bytes(32)
        assert generate_key.mix_entropy(user) != generate_key.mix_entropy(user)


class TestCollectDiceEntropy:
    def test_hashes_concatenated_rolls(self, monkeypatch):
        rolls = "123456" * 17  # 102 rolls
        monkeypatch.setattr("builtins.input", lambda _: rolls)
        assert generate_key.collect_dice_entropy() == hashlib.sha256(rolls.encode()).digest()

    def test_accumulates_batches_and_strips_spaces(self, monkeypatch):
        batches = iter(["1234 56" * 10, "654321" * 10])
        monkeypatch.setattr("builtins.input", lambda _: next(batches))
        expected = hashlib.sha256(("123456" * 10 + "654321" * 10).encode()).digest()
        assert generate_key.collect_dice_entropy() == expected

    def test_rejects_non_dice_digits(self, monkeypatch):
        lines = iter(["978", "abc", "123456" * 17])
        monkeypatch.setattr("builtins.input", lambda _: next(lines))
        assert generate_key.collect_dice_entropy() == hashlib.sha256(("123456" * 17).encode()).digest()

    def test_keeps_prompting_below_minimum(self, monkeypatch):
        short = "1" * (generate_key.MIN_DICE_ROLLS - 1)
        lines = iter([short, "2"])
        monkeypatch.setattr("builtins.input", lambda _: next(lines))
        assert generate_key.collect_dice_entropy() == hashlib.sha256((short + "2").encode()).digest()


class TestCollectKeyboardEntropy:
    def test_returns_deterministic_hash_of_keys_and_timings(self, monkeypatch):
        chars = iter("a" * generate_key.MIN_KEYSTROKES)

        class FakeStdin:
            def fileno(self):
                return 0

            def read(self, n):
                return next(chars)

        monkeypatch.setattr(generate_key.sys, "stdin", FakeStdin())
        monkeypatch.setattr(generate_key.termios, "tcgetattr", lambda fd: "old")
        monkeypatch.setattr(generate_key.termios, "tcsetattr", lambda fd, when, attrs: None)
        monkeypatch.setattr(generate_key.tty, "setcbreak", lambda fd: None)
        monkeypatch.setattr(generate_key.time, "perf_counter_ns", lambda: 12345)

        expected = hashlib.sha256(
            "|".join(f"{'a'!r}:12345" for _ in range(generate_key.MIN_KEYSTROKES)).encode()
        ).digest()
        assert generate_key.collect_keyboard_entropy() == expected

    def test_restores_terminal_settings_on_error(self, monkeypatch):
        restored = []

        class FakeStdin:
            def fileno(self):
                return 0

            def read(self, n):
                raise KeyboardInterrupt

        monkeypatch.setattr(generate_key.sys, "stdin", FakeStdin())
        monkeypatch.setattr(generate_key.termios, "tcgetattr", lambda fd: "old")
        monkeypatch.setattr(
            generate_key.termios, "tcsetattr", lambda fd, when, attrs: restored.append(attrs)
        )
        monkeypatch.setattr(generate_key.tty, "setcbreak", lambda fd: None)

        with pytest.raises(KeyboardInterrupt):
            generate_key.collect_keyboard_entropy()
        assert restored == ["old"]


class TestChooseEntropySource:
    def test_choice_1_collects_dice(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "1")
        monkeypatch.setattr(generate_key, "collect_dice_entropy", lambda: b"d" * 32)
        assert generate_key.choose_entropy_source() == b"d" * 32

    def test_choice_2_collects_keyboard(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "2")
        monkeypatch.setattr(generate_key, "collect_keyboard_entropy", lambda: b"k" * 32)
        assert generate_key.choose_entropy_source() == b"k" * 32

    def test_reprompts_on_invalid_choice(self, monkeypatch):
        answers = iter(["x", "3", "2"])
        monkeypatch.setattr("builtins.input", lambda _: next(answers))
        monkeypatch.setattr(generate_key, "collect_keyboard_entropy", lambda: b"k" * 32)
        assert generate_key.choose_entropy_source() == b"k" * 32


class TestGenerateSeedPhrase:
    def test_bip39_test_vector(self, monkeypatch, capsys):
        # 32 zero bytes is the canonical BIP-39 vector: abandon x23 + art
        monkeypatch.setattr(generate_key, "mix_entropy", lambda user: bytes(32))
        generate_key.generate_seed_phrase(b"unused")
        phrase = capsys.readouterr().out.strip().removeprefix("Seed Phrase: ")
        words = phrase.split()
        assert len(words) == 24
        assert words[:2] == ["abandon", "abandon"]
        assert words[-1] == "art"


class TestGeneratePrivateKey:
    def test_known_key_and_address(self, monkeypatch, capsys):
        monkeypatch.setattr(generate_key, "mix_entropy", lambda user: bytes(31) + b"\x01")
        generate_key.generate_private_key(b"unused")
        out = capsys.readouterr().out
        assert "Private Key: " + "00" * 31 + "01" in out
        assert "Wallet Address: 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf" in out

    def test_retries_until_key_is_in_range(self, monkeypatch, capsys):
        attempts = iter([bytes(32), bytes(31) + b"\x01"])  # invalid (zero), then valid
        monkeypatch.setattr(generate_key, "mix_entropy", lambda user: next(attempts))
        generate_key.generate_private_key(b"unused")
        assert "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf" in capsys.readouterr().out


class TestMain:
    def test_default_generates_seed_phrase(self, monkeypatch, capsys):
        monkeypatch.setattr(generate_key.sys, "argv", ["generate_key.py"])
        monkeypatch.setattr(generate_key, "choose_entropy_source", lambda: b"u" * 32)
        monkeypatch.setattr(generate_key, "mix_entropy", lambda user: bytes(32))
        generate_key.main()
        assert "Seed Phrase: " in capsys.readouterr().out

    def test_pk_flag_generates_private_key(self, monkeypatch, capsys):
        monkeypatch.setattr(generate_key.sys, "argv", ["generate_key.py", "--pk"])
        monkeypatch.setattr(generate_key, "choose_entropy_source", lambda: b"u" * 32)
        monkeypatch.setattr(generate_key, "mix_entropy", lambda user: bytes(31) + b"\x01")
        generate_key.main()
        assert "Wallet Address: " in capsys.readouterr().out
