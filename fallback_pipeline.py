#!/usr/bin/env python3

import asyncio, subprocess, os, json, time, traceback
from dotenv import load_dotenv
load_dotenv("malwarescope/.env")

from claude_agent_sdk import (
    tool, create_sdk_mcp_server, query,
    ClaudeAgentOptions, AssistantMessage, ResultMessage, TextBlock, ToolUseBlock,
)

CONTAINER = "malware-sandbox"
WORKSPACE = os.path.abspath("workspace")
os.makedirs(WORKSPACE, exist_ok=True)
OUTPUT_CAP = 4000
start_time = time.time()
G, R, Y, B, RS = "\033[32m", "\033[31m", "\033[33m", "\033[1m", "\033[0m"


def el(): return time.time() - start_time
def log(c, t, m): print(f"\033[90m{el():6.1f}s{RS} {c}{t:>10}{RS}  {m}", flush=True)
def cap(o):
    return o[:OUTPUT_CAP] + f"\n...[{len(o)}ch total]" if len(o) > OUTPUT_CAP else o


@tool("sandbox", "Run bash in Docker sandbox.", {"command": str})
async def sandbox(args):
    try:
        r = subprocess.run(["docker", "exec", CONTAINER, "bash", "-c", args["command"]],
                           capture_output=True, text=True, timeout=120)
        out = cap((r.stdout + r.stderr).strip())
        log(G, "RESULT", f"{len(out)}ch")
        return {"content": [{"type": "text", "text": out or "(no output)"}]}
    except Exception as e:
        return {"content": [{"type": "text", "text": f"Error: {e}"}], "is_error": True}


@tool("host_analyze", "Run on HOST for pefile/ilspycmd.", {"command": str})
async def host_analyze(args):
    try:
        env = {**os.environ, "DOTNET_ROOT": "/opt/homebrew/opt/dotnet@8/libexec"}
        r = subprocess.run(["bash", "-c", args["command"]],
                           capture_output=True, text=True, timeout=120, cwd=WORKSPACE, env=env)
        out = cap((r.stdout + r.stderr).strip())
        log(G, "RESULT", f"{len(out)}ch")
        return {"content": [{"type": "text", "text": out or "(no output)"}]}
    except Exception as e:
        return {"content": [{"type": "text", "text": f"Error: {e}"}], "is_error": True}


@tool("extract_file", "Copy from Docker to host workspace.", {"container_path": str, "host_filename": str})
async def extract_file(args):
    hp = os.path.join(WORKSPACE, args["host_filename"])
    try:
        r = subprocess.run(["docker", "cp", f"{CONTAINER}:{args['container_path']}", hp],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            return {"content": [{"type": "text", "text": f"Saved {hp} ({os.path.getsize(hp)} bytes)"}]}
        return {"content": [{"type": "text", "text": f"Failed: {r.stderr}"}], "is_error": True}
    except Exception as e:
        return {"content": [{"type": "text", "text": f"Error: {e}"}], "is_error": True}


server = create_sdk_mcp_server(name="m", version="1.0.0", tools=[sandbox, host_analyze, extract_file])

BASE_OPTS = dict(
    system_prompt="You are a malware analyst. Execute exactly what is asked. One tool call.",
    tools=[],
    mcp_servers={"m": server},
    allowed_tools=["mcp__m__sandbox", "mcp__m__host_analyze", "mcp__m__extract_file"],
    permission_mode="bypassPermissions",
    model="sonnet",
    effort="low",
    thinking={"type": "disabled"},
    setting_sources=[],
    env={"CLAUDE_CODE_MAX_OUTPUT_TOKENS": "8000"},
)


async def step(prompt, session_id=None, max_turns=10):
    opts = {**BASE_OPTS, "max_turns": max_turns}
    if session_id:
        opts["resume"] = session_id
    result_text = ""
    sid = session_id
    async for msg in query(prompt=prompt, options=ClaudeAgentOptions(**opts)):
        if isinstance(msg, AssistantMessage):
            for b in msg.content:
                if isinstance(b, TextBlock):
                    log(B, "TEXT", b.text[:200].replace("\n", " "))
                elif isinstance(b, ToolUseBlock):
                    c = b.input.get("command", b.input.get("container_path", ""))
                    log(Y, "CALL", f"{b.name}: {str(c)[:120]}")
        elif isinstance(msg, ResultMessage):
            sid = msg.session_id
            result_text = msg.result or ""
            log(G, "STEP", f"turns={msg.num_turns} cost=${msg.total_cost_usd or 0:.4f} stop={msg.subtype}")
    return sid, result_text


async def main():
    log(B, "START", "Pipeline")

    # Hashes
    r = subprocess.run(["docker", "exec", CONTAINER, "python3", "-c", """
import hashlib
with open("/sample/6108674530.JS.malicious","rb") as f: d=f.read()
print(f"md5:{hashlib.md5(d).hexdigest()} sha256:{hashlib.sha256(d).hexdigest()} size:{len(d)}")
"""], capture_output=True, text=True)
    hashes = r.stdout.strip()
    log(G, "HASHES", hashes[:100])

    # Step 1: Find and decode PowerShell from raw sample line 826
    sid, txt = await step(f"""Hashes: {hashes}

Run ONE sandbox python3 script that does ALL of this:
1. Read line 826 (index 825) from /workspace/raw_sample.js
2. Use regex to find all runs of [A-Za-z0-9+/=]{{100,}} in that line
3. For each run: strip all occurrences of 'IMLRHNEGA', base64 decode, try UTF-16LE decode
4. If the decoded text contains 'FromBase64String', print it and save to /workspace/ps.txt
5. Print how many runs were checked and which one matched""")

    log(B, "STEP1", f"PowerShell extraction. Got {len(txt)} chars")

    # Step 2: Extract AES key and decrypt payload
    sid, txt = await step("""Read /workspace/ps.txt. Find the two FromBase64String('...') calls — one is the AES key (~32 bytes), one is the IV (~16 bytes).
Then read variable JESOUINA from /workspace/restringer_output.js (grep for "var JESOUINA" or find the ~185944 char string near line 1223).
AES-256-CBC decrypt with PKCS7 unpad using the cryptography library (not pycryptodome).
Save decrypted to /workspace/decrypted.bin.
Print: key_b64, iv_b64, decrypted_size, first_4_bytes_hex.
Do this ALL in ONE sandbox python3 script.""", session_id=sid)

    log(B, "STEP2", f"AES decrypt. Got {len(txt)} chars")

    # Step 3: Extract to host
    sid, txt = await step(
        "Use extract_file to copy /workspace/decrypted.bin to host as decrypted.bin.",
        session_id=sid)

    log(B, "STEP3", f"Extract. Got {len(txt)} chars")

    # Step 4: PE analysis + ILSpy decompile + grep for IOCs
    sid, txt = await step("""Run ONE host_analyze bash command:
python3 -c "
import pefile, hashlib
pe=pefile.PE('decrypted.bin')
d=open('decrypted.bin','rb').read()
print('Machine:',hex(pe.FILE_HEADER.Machine))
print('Sections:',len(pe.sections))
for s in pe.sections: print(f'  {s.Name.decode().strip(chr(0))}: {s.SizeOfRawData}b ent={s.get_entropy():.2f}')
clr=pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
print('.NET:','YES' if clr.VirtualAddress>0 else 'NO')
print('MD5:',hashlib.md5(d).hexdigest())
print('SHA256:',hashlib.sha256(d).hexdigest())
" && ~/.dotnet/tools/ilspycmd decrypted.bin -p -o ilspy_out 2>&1 | tail -3 && grep -rn "ftp://\|[Pp]assword\|WebClient\|KeyloggerInterval\|SetWindowsHookEx\|FtpWebRequest\|clipboard\|Credential" ilspy_out/ 2>/dev/null | head -40""",
        session_id=sid)

    log(B, "STEP4", f"PE analysis. Got {len(txt)} chars")

    # Step 5: Write report (max_turns=0 forces text-only, no tools)
    sid, txt = await step("""Write your complete malware analysis findings report. Include:
1. Executive summary (verdict, kill chain)
2. All hashes (JS dropper + .NET payload)
3. Full execution chain (JS → PowerShell → AES decrypt → .NET load)
4. AES key and IV (base64)
5. C2 infrastructure (URLs, IPs, credentials from ilspy grep)
6. Capabilities (keylogger, clipboard, credential theft, etc from ilspy grep)
7. MITRE ATT&CK techniques
8. IOCs""",
        session_id=sid, max_turns=1)

    log(B, "DONE", f"Report: {len(txt)} chars, Total: {el():.0f}s")

    if txt:
        with open(os.path.join(WORKSPACE, "findings.txt"), "w") as f:
            f.write(txt)
        print(f"\n{'='*60}\n{txt}\n{'='*60}")
    else:
        log(R, "EMPTY", "No findings produced")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{R}Interrupted{RS}")
    except Exception as e:
        print(f"\n{R}{type(e).__name__}: {e}{RS}")
        traceback.print_exc()
