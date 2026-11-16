from app.config import Settings


def test_gemini_key_is_read_but_hidden_when_printed():
    loaded = Settings(gemini_api_key="not-a-real-key-123")
    assert loaded.gemini_api_key.get_secret_value() == "not-a-real-key-123"
    assert "not-a-real-key-123" not in repr(loaded)
    assert "not-a-real-key-123" not in str(loaded)


def test_gemini_model_defaults_to_flash_lite():
    assert Settings().gemini_model == "gemini-3.5-flash-lite"