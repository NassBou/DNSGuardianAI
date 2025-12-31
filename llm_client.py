import requests
import json
import re
import time
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any


class LLMClient:
    def __init__(self, model: str, api_url: str, timeout: float = 30.0,
                 enable_logging: bool = False, enable_reasoning_log: bool = False,
                 log_dir: Optional[str] = None, api_key: Optional[str] = None):
        self.model = model
        self.api_url = api_url
        self.timeout = timeout
        self.enable_logging = enable_logging
        self.enable_reasoning_log = enable_reasoning_log

        # --- auth & headers (OpenAI / Azure / local OpenAI-compatible) ---
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.headers: Dict[str, str] = {"Content-Type": "application/json"}

        if "openai.com" in self.api_url:
            # Official OpenAI API
            if self.api_key:
                self.headers["Authorization"] = f"Bearer {self.api_key}"
            org = os.environ.get("OPENAI_ORG_ID")
            if org:
                self.headers["OpenAI-Organization"] = org
        elif ".azure.com" in self.api_url:
            # Azure OpenAI (OpenAI-compatible path w/ api-version)
            if self.api_key:
                self.headers["api-key"] = self.api_key
        else:
            # Local OpenAI-compatible servers
            if self.api_key and "Authorization" not in self.headers and "api-key" not in self.headers:
                self.headers["Authorization"] = f"Bearer {self.api_key}"

        # --- logging dirs ---
        self.log_root = Path(log_dir or os.environ.get("LLM_LOG_DIR", "logs"))
        self.run_dir = self.log_root / time.strftime("%Y%m%d")
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.http_jsonl = self.run_dir / "http.jsonl"
        self.assistant_jsonl = self.run_dir / "assistant_responses.jsonl"
        self.thinking_jsonl = self.run_dir / "thinking.jsonl"
        # legacy text logs (kept)
        self.raw_log_path = str(self.run_dir / "llm_raw_log.txt")
        self.reason_log_path = str(self.run_dir / "llm_reasoning_log.txt")

    # ------------------ MAIN CALL ------------------
    def _call_llm(self, prompt: str, domain_for_logging: str, max_tokens=768) -> dict:
        """
        Each call is a fresh chat (no history). A unique chat_id is generated per request.
        """
        chat_id = f"{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a cybersecurity analyst. Think carefully and reason internally, "
                        'but end your message with ONLY a single JSON object in this format: '
                        '{"verdict":"Safe|Malicious|Likely Phishing|Possibly Legitimate","mimics":null|"example.com"}'
                    ),
                },
                {"role": "user", "content": prompt},
            ],
        }
        # Token field compatibility
        m = (self.model or "").lower()
        if m.startswith("gpt-5") or m.startswith("gpt-4o"):
            payload["max_completion_tokens"] = max_tokens
        else:
            payload["max_tokens"] = max_tokens

        start = time.perf_counter()
        response = None
        try:
            response = requests.post(
                self.api_url,
                headers=self.headers,
                json=payload,
                timeout=self.timeout,
            )
            latency_ms = (time.perf_counter() - start) * 1000

            if self.enable_logging:
                self._log_http(domain_for_logging, payload, response, latency_ms, chat_id=chat_id)

            if response.status_code != 200:
                return {
                    "verdict": "Error",
                    "reason": f"HTTP {response.status_code}: {response.text[:300]}",
                }

            content = self._extract_content(response.json())

            if self.enable_logging:
                self._log_assistant(domain_for_logging, content, chat_id=chat_id)

            if self.enable_reasoning_log:
                think = re.search(r"<think>([\s\S]*?)</think>", content)
                if think:
                    with open(self.reason_log_path, "a", encoding="utf-8") as f:
                        f.write(f"\n[{domain_for_logging}] ({chat_id})\n")
                        f.write(think.group(1).strip() + "\n" + "-" * 70 + "\n")

            match = re.search(r"\{[\s\S]*\}", content)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    return {"verdict": "Error", "reason": "Invalid JSON format"}

            return {"verdict": "Error", "reason": "No JSON found in LLM response"}

        except Exception as e:
            latency_ms = (time.perf_counter() - start) * 1000
            if self.enable_logging:
                self._log_http(domain_for_logging, payload, response, latency_ms, error=e, chat_id=chat_id)
            return {"verdict": "Error", "reason": str(e)}

    # ------------------ HELPERS ------------------
    def _extract_content(self, data: dict) -> str:
        try:
            return data["choices"][0]["message"]["content"]
        except Exception:
            return json.dumps(data)

    def _write_jsonl(self, path: Path, record: Dict[str, Any]):
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def _log_http(self, domain, payload, response, latency_ms, error=None, chat_id=None):
        rec: Dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "chat_id": chat_id,
            "domain": domain,
            "latency_ms": round(latency_ms, 2),
            "request": payload,
            "status": getattr(response, "status_code", None),
        }
        try:
            if response is not None:
                try:
                    rec["response"] = response.json()
                except Exception:
                    rec["response_text"] = getattr(response, "text", None)
        except Exception:
            pass
        if error:
            rec["error"] = str(error)
        self._write_jsonl(self.http_jsonl, rec)

        # legacy flat log
        try:
            with open(self.raw_log_path, "a", encoding="utf-8") as f:
                f.write(f"\nTime: {rec['ts']}\n")
                f.write(f"Chat: {chat_id}\n")
                f.write(f"Domain: {domain}\n")
                f.write(f"Latency(ms): {rec['latency_ms']:.2f}\n")
                f.write(f"Request Payload: {json.dumps(payload, indent=2)}\n")
                f.write(f"Response Status: {rec.get('status')}\n")
                if 'response' in rec:
                    f.write(f"Response JSON: {json.dumps(rec['response'], ensure_ascii=False)[:20000]}\n")
                elif 'response_text' in rec and rec['response_text'] is not None:
                    f.write(f"Response Body: {rec['response_text'][:20000]}\n")
                if error:
                    f.write(f"Error: {error}\n")
                f.write("-" * 80 + "\n")
        except Exception:
            pass

    def _log_assistant(self, domain: str, content: str, chat_id=None):
        rec = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "chat_id": chat_id,
            "domain": domain,
            "assistant_content": content,
        }
        self._write_jsonl(self.assistant_jsonl, rec)
        think = re.search(r"<think>([\s\S]*?)</think>", content)
        if think:
            self._write_jsonl(self.thinking_jsonl, {
                "ts": rec["ts"],
                "chat_id": chat_id,
                "domain": domain,
                "thinking": think.group(1).strip(),
            })

    #===================================================================================================
    def san_check(self, domain: str, san_list: list[str]) -> dict:
        if not san_list or len(san_list) <= 1:
            return {"verdict": "Safe", "reason": "Single SAN — normal"}

        domain = domain.lower().strip('.')
        san_str = ', '.join([s.strip('.') for s in san_list])

        prompt = (
            f"A TLS certificate for `{domain}` includes the following SANs: {san_str}. "
            "Is this a legitimate set of names or does it seem suspicious? "
            "Reply ONLY in JSON format: "
            '{"verdict": "Safe", "reason": "..."} or {"verdict": "Suspicious", "reason": "..."}'
        )

        # FIX: pass domain_for_logging
        return self._call_llm(prompt, domain_for_logging=domain)

    #===================================================================================================
    def phishing_check(self, domain: str, title: str = "", **kwargs) -> dict:
        prompt = (
            f"Analyze domain `{domain}`. "
            f"{'Page title: ' + title + '. ' if title else ''}"
            "Return ONLY JSON: "
            '{"verdict":"Safe|Malicious|Likely Phishing|Possibly Legitimate","mimics":null|"example.com"}'
        )
        return self._call_llm(prompt, domain_for_logging=domain)
