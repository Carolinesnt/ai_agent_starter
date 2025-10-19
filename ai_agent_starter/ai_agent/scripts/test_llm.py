#!/usr/bin/env python3
"""
Quick LLM connectivity test for OpenAI or Gemini based on .env

Usage:
  python ai_agent_starter/ai_agent/scripts/test_llm.py
"""
import os
import sys
import json
from pathlib import Path

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None


def info(msg: str):
    print(f"[INFO] {msg}")


def ok(msg: str):
    print(f"[OK] {msg}")


def fail(msg: str):
    print(f"[FAIL] {msg}")


def test_openai():
    try:
        from openai import OpenAI
    except Exception as e:
        fail(f"OpenAI SDK not installed: {e}")
        return False
    api_key = os.getenv("OPENAI_API_KEY")
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    if not api_key:
        fail("OPENAI_API_KEY is empty")
        return False
    try:
        client = OpenAI()
        resp = client.chat.completions.create(
            model=model,
            response_format={"type": "json_object"},
            temperature=0,
            messages=[
                {
                    "role": "system",
                    "content": "Return strictly a compact JSON object with key ok=true",
                },
                {"role": "user", "content": "Respond with {\"ok\": true}"},
            ],
        )
        content = resp.choices[0].message.content
        data = json.loads(content)
        if isinstance(data, dict) and data.get("ok") is True:
            ok(f"OpenAI connected (model={model})")
            return True
        fail("OpenAI responded but JSON did not match {ok:true}")
        return False
    except Exception as e:
        fail(f"OpenAI call failed: {e}")
        return False


def test_gemini():
    try:
        import google.generativeai as genai
        try:
            try:
                # Python 3.8+: stdlib way to get package version
                import importlib.metadata as importlib_metadata
            except Exception:
                import importlib_metadata  # type: ignore
            ver = importlib_metadata.version("google-generativeai")
            info(f"google-generativeai version={ver}")
        except Exception:
            pass
    except Exception as e:
        fail(f"google-generativeai not installed: {e}")
        return False
    api_key = os.getenv("GEMINI_API_KEY")
    # Seed with env and common aliases; we'll augment with server-supported list below
    env_model = os.getenv("GEMINI_MODEL")
    preferred = [m for m in [env_model, "gemini-2.5-flash", "gemini-2.5-pro", "gemini-flash-latest", "gemini-pro-latest", "gemini-1.5-flash", "gemini-1.5-pro", "gemini-pro"] if m]
    if not api_key:
        fail("GEMINI_API_KEY is empty")
        return False
    try:
        genai.configure(api_key=api_key)
        last_err = None
        # Discover server-supported models for generateContent and extend the try list
        try:
            models = genai.list_models()
            supported = [m.name for m in models if 'generateContent' in getattr(m, 'supported_generation_methods', [])]
            # Prefer 2.5 flash/pro first if available
            preferred_order = []
            for key in ("models/gemini-2.5-flash", "models/gemini-2.5-pro", "models/gemini-flash-latest", "models/gemini-pro-latest"):
                if key in supported:
                    preferred_order.append(key)
            # Add all supported at the end to ensure we try at least one working
            for name in supported:
                if name not in preferred_order:
                    preferred_order.append(name)
            # If env model provided without prefix, add prefixed variant too
            if env_model and not env_model.startswith("models/"):
                preferred.insert(0, f"models/{env_model}")
            # Merge, keeping order and uniqueness
            seen = set()
            merged = []
            for m in preferred + preferred_order:
                if m and m not in seen:
                    seen.add(m)
                    merged.append(m)
            preferred = merged
        except Exception:
            supported = []
        for model in preferred:
            try:
                gm = genai.GenerativeModel(model)
                resp = gm.generate_content(
                    'Respond with JSON: {"ok": true}',
                    generation_config={"response_mime_type": "application/json"},
                )
                text = getattr(resp, "text", None)
                if not text and getattr(resp, "candidates", None):
                    try:
                        text = resp.candidates[0].content.parts[0].text
                    except Exception:
                        text = None
                data = json.loads(text or "{}")
                if isinstance(data, dict) and data.get("ok") is True:
                    ok(f"Gemini connected (model={model})")
                    return True
                last_err = f"Unexpected JSON: {text}"
            except Exception as e:
                last_err = str(e)
        if 'supported' in locals() and supported:
            fail(f"Gemini call failed: {last_err}. Available models supporting generateContent: {supported}")
        else:
            fail(f"Gemini call failed: {last_err}")
        return False
    except Exception as e:
        fail(f"Gemini call failed: {e}")
        return False


def main():
    # Load .env from repo root
    if load_dotenv:
        # Try project root two levels up
        root = Path(__file__).resolve().parents[2]
        env_path = root / ".env"
        if env_path.exists():
            load_dotenv(env_path)
        else:
            load_dotenv()

    provider = (os.getenv("LLM_PROVIDER") or "openai").strip().lower()
    info(f"LLM_PROVIDER={provider}")
    if provider == "gemini":
        ok_ = test_gemini()
    elif provider in ("openai", ""):
        ok_ = test_openai()
    else:
        fail(f"Unknown provider: {provider}")
        ok_ = False
    sys.exit(0 if ok_ else 1)


if __name__ == "__main__":
    main()
