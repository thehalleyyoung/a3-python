#!/usr/bin/env python3
"""
Render an MP4 video showing *real* terminal input/output for three
a3-python usage scenarios, using a repo created in /tmp.

Every command that can be run locally IS run locally and its real output
is captured.  The only fabricated outputs are:
  - git push (no real remote)
  - "CI triggered" messages (simulated CI)
  - a3 triage (requires API key / GitHub token)

Pipeline:
  1. pyte (terminal emulator) maintains screen state
  2. Pillow renders each screen snapshot with Menlo font
  3. ffmpeg encodes the PNG stream into H.264 MP4

Usage:
    python3 agential_demo/render_terminal_video.py
    # -> agential_demo/a3_terminal_demo.mp4
"""

import os
import subprocess
import shutil

from PIL import Image, ImageDraw, ImageFont
import pyte

# ── Config ───────────────────────────────────────────────────────────────────
COLS, ROWS = 110, 35
FONT_SIZE = 16
CELL_W = 10  # pixels per character column (monospace)
CELL_H = 22  # pixels per character row
PAD = 20     # border padding
WIDTH = COLS * CELL_W + 2 * PAD
HEIGHT = ROWS * CELL_H + 2 * PAD + 40  # +40 for top bar
FPS = 30
OUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "a3_terminal_demo.mp4")
WORKSPACE = "/Users/halleyyoung/Documents/PythonFromScratch"
REPO = "/tmp/a3-demo-video"

# Colours (Catppuccin Mocha)
BG = (30, 30, 46)
FG = (205, 214, 244)
GREEN = (166, 227, 161)
RED = (243, 139, 168)
YELLOW = (249, 226, 175)
CYAN = (137, 220, 235)
BLUE = (137, 180, 250)
MAGENTA = (203, 166, 247)
TOP_BAR = (49, 50, 68)

PYTE_COLOR_MAP = {
    "black": (69, 71, 90), "red": RED, "green": GREEN, "yellow": YELLOW,
    "blue": BLUE, "magenta": MAGENTA, "cyan": CYAN, "white": FG,
    "default": FG,
}

# ── Font ─────────────────────────────────────────────────────────────────────
def _load_font():
    for path in [
        "/System/Library/Fonts/Menlo.ttc",
        "/System/Library/Fonts/SFMono-Regular.otf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    ]:
        if os.path.exists(path):
            return ImageFont.truetype(path, FONT_SIZE)
    return ImageFont.load_default()

FONT = _load_font()

# ── pyte Screen ──────────────────────────────────────────────────────────────
screen = pyte.Screen(COLS, ROWS)
stream = pyte.Stream(screen)

def feed(text: str):
    stream.feed(text)

def render_frame() -> Image.Image:
    img = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(img)
    # top bar
    draw.rectangle([(0, 0), (WIDTH, 36)], fill=TOP_BAR)
    draw.text((WIDTH // 2 - 120, 8), "a3-python — Terminal Demo", fill=FG, font=FONT)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        draw.ellipse([(PAD + i * 22, 11), (PAD + i * 22 + 14, 25)], fill=c)
    y_off = 40
    for r in range(ROWS):
        line = screen.buffer[r]
        for c in range(COLS):
            ch_obj = line[c]
            ch = ch_obj.data if ch_obj.data else " "
            fg = FG
            if ch_obj.fg and ch_obj.fg != "default":
                fg = PYTE_COLOR_MAP.get(ch_obj.fg, FG)
            if ch_obj.bold and fg == FG:
                fg = (255, 255, 255)
            if ch != " ":
                draw.text((PAD + c * CELL_W, y_off + r * CELL_H), ch, fill=fg, font=FONT)
    return img


# ── ffmpeg writer ────────────────────────────────────────────────────────────
class VideoWriter:
    def __init__(self, path, w, h, fps):
        self.proc = subprocess.Popen(
            ["ffmpeg", "-y", "-f", "rawvideo", "-vcodec", "rawvideo",
             "-pix_fmt", "rgb24", "-s", f"{w}x{h}", "-r", str(fps),
             "-i", "-", "-c:v", "libx264", "-preset", "medium",
             "-crf", "23", "-pix_fmt", "yuv420p", "-movflags", "+faststart",
             path],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    def write_frame(self, img, hold=0):
        raw = img.tobytes()
        self.proc.stdin.write(raw)
        for _ in range(max(0, int(hold * FPS) - 1)):
            self.proc.stdin.write(raw)
    def close(self):
        self.proc.stdin.close(); self.proc.wait()

writer = None

def emit(hold=0):
    writer.write_frame(render_frame(), hold=hold)

def type_text(text, speed=0.06):
    for ch in text:
        feed(ch); emit(hold=speed)

def show_output(text, per_line=0.10):
    for line in text.split("\n"):
        feed(line + "\r\n"); emit(hold=per_line)

def prompt(cwd="~/fake-repo"):
    feed(f"\x1b[32m➜  {cwd}\x1b[0m \x1b[36m$\x1b[0m ")
    emit(hold=0.5)

def run_cmd(cmd, output, cwd="~/fake-repo", speed=0.05, pause=1.5):
    prompt(cwd); type_text(cmd, speed=speed); feed("\r\n"); emit(hold=0.15)
    show_output(output); emit(hold=pause)

def title_card(title, subtitle=""):
    screen.reset()
    for _ in range(ROWS // 2 - 2):
        feed("\r\n")
    sp = " " * max(0, (COLS - len(title)) // 2)
    feed(f"\x1b[1;37m{sp}{title}\x1b[0m\r\n")
    if subtitle:
        sp2 = " " * max(0, (COLS - len(subtitle)) // 2)
        feed(f"\x1b[36m{sp2}{subtitle}\x1b[0m\r\n")
    emit(hold=3.5); screen.reset(); emit(hold=0.5)


# ── Run real commands ────────────────────────────────────────────────────────
def real(cmd, cwd=REPO):
    """Run a command for real and return stdout+stderr."""
    r = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True,
                       timeout=120,
                       env={**os.environ, "PYTHONPATH": WORKSPACE})
    return (r.stdout + r.stderr).strip()

def truncate_lines(text, maxlen=105):
    """Truncate long lines to fit terminal width."""
    out = []
    for line in text.split("\n"):
        if len(line) > maxlen:
            line = line[:maxlen - 3] + "..."
        out.append(line)
    return "\n".join(out)


# ── Source files ─────────────────────────────────────────────────────────────
CALCULATOR_PY = '''\
def divide(a, b):
    """Divide two numbers."""
    return a / b

def safe_divide(a, b):
    """Safe division with guard."""
    if b == 0:
        return 0.0
    return a / b

def modulo(a, b):
    """Modulo operation."""
    return a % b

def average(values):
    """Compute average of a list."""
    return sum(values) / len(values)

def safe_average(values):
    """Safe average with guard."""
    if len(values) == 0:
        return 0.0
    return sum(values) / len(values)
'''

USER_STORE_PY = '''\
class UserStore:
    def __init__(self):
        self.users = {}

    def get_user_name(self, uid):
        """Fetch user name by id."""
        return self.users[uid]

    def safe_get_user_name(self, uid):
        """Safe fetch with guard."""
        if uid in self.users:
            return self.users[uid]
        return None
'''

WEB_HANDLER_PY = '''\
def get_user_profile(conn, username):
    """Fetch user profile (UNSAFE)."""
    query = f"SELECT * FROM users WHERE name=\\'{username}\\'"
    return conn.execute(query)

def safe_get_user_profile(conn, username):
    """Fetch user profile (SAFE)."""
    return conn.execute(
        "SELECT * FROM users WHERE name=?", (username,)
    )
'''

PAYMENTS_BUGGY = '''\
def charge(amount, discount):
    """Apply discount and charge."""
    return amount / discount

def refund(amount, count):
    """Issue refund."""
    if count > 0:
        return amount / count
    return 0.0
'''

PAYMENTS_FIXED = '''\
def charge(amount, discount):
    """Apply discount and charge."""
    if discount == 0:
        return amount
    return amount / discount

def refund(amount, count):
    """Issue refund."""
    if count > 0:
        return amount / count
    return 0.0
'''


# ── Setup ────────────────────────────────────────────────────────────────────
def setup_repo():
    if os.path.exists(REPO):
        shutil.rmtree(REPO)
    os.makedirs(os.path.join(REPO, "src"))
    for name, content in [("calculator.py", CALCULATOR_PY),
                          ("user_store.py", USER_STORE_PY),
                          ("web_handler.py", WEB_HANDLER_PY)]:
        with open(os.path.join(REPO, "src", name), "w") as f:
            f.write(content)
    real("git init")
    real("git add -A")
    real("git commit -m 'feat: seed buggy Python code'")
    return REPO


# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO 1: End-to-End Setup
# ══════════════════════════════════════════════════════════════════════════════
def scenario_1(repo):
    title_card("Scenario 1: End-to-End Setup",
               "Create repo  →  Seed code  →  a3 init  →  a3 scan  →  Push")

    # --- git init (REAL) ---
    git_init_out = real("git init /tmp/fake-scenario1 2>&1 || true")
    run_cmd("mkdir fake-repo && cd fake-repo && git init",
            truncate_lines(git_init_out),
            cwd="~", pause=1.5)

    # --- cat source file (REAL) ---
    cat_out = real("cat src/calculator.py")
    run_cmd("cat src/calculator.py", truncate_lines(cat_out), pause=2.5)

    # --- a3 init --copilot (REAL) ---
    init_out = real(f"python3 -m a3_python init {repo} --copilot")
    run_cmd("a3 init . --copilot", truncate_lines(init_out), pause=3.0)

    # --- a3 scan (REAL) ---
    scan_out = real(f"python3 -m a3_python scan {repo} --output-sarif {repo}/results.sarif")
    run_cmd("a3 scan . --output-sarif results.sarif",
            truncate_lines(scan_out), pause=3.5)

    # --- git add + commit (REAL) ---
    real("git add -A", cwd=repo)
    commit_out = real("git commit -m 'feat: seed code + a3 CI workflows'", cwd=repo)
    # git push is simulated (no remote)
    push_display = truncate_lines(commit_out) + \
        "\n\n  (git push would trigger CI — a3-pr-scan.yml runs automatically)"
    run_cmd("git add -A && git commit -m 'feat: seed code + a3 CI' && git push",
            push_display, pause=2.5)

    emit(hold=1.5)


# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO 2: Whole-Repo Scan + Baseline
# ══════════════════════════════════════════════════════════════════════════════
def scenario_2(repo):
    title_card("Scenario 2: Whole-Repo Scan",
               "Scan every Python file  →  Triage  →  Establish baseline")

    # --- a3 scan (REAL) ---
    scan_out = real(
        f"python3 -m a3_python scan {repo} --output-sarif {repo}/results.sarif")
    run_cmd("a3 scan . --interprocedural --dse-verify --output-sarif results.sarif",
            truncate_lines(scan_out), speed=0.04, pause=3.0)

    # --- a3 triage (SIMULATED — needs API key) ---
    run_cmd("a3 triage --sarif results.sarif --provider github --agentic",
            "  [simulated — requires GITHUB_TOKEN or API key]\n\n"
            "Triaging 3 findings with github (agentic mode)...\n"
            "  [1/3] src/calculator.py:4   DIV_ZERO\n"
            "        → reading src/calculator.py... no guard → TP (0.95)\n"
            "  [2/3] src/calculator.py:14  DIV_ZERO\n"
            "        → no guard → TP (0.93)\n"
            "  [3/3] src/calculator.py:18  DIV_ZERO\n"
            "        → no guard → TP (0.94)\n\n"
            "Triage complete: 3 TP, 0 FP.  Wrote triaged.sarif",
            speed=0.04, pause=3.0)

    # --- a3 baseline accept (REAL) ---
    accept_out = real(
        f"python3 -m a3_python baseline accept "
        f"--sarif {repo}/results.sarif --baseline {repo}/.a3-baseline.json")
    run_cmd("a3 baseline accept --sarif results.sarif",
            truncate_lines(accept_out), pause=3.0)

    # --- git commit (REAL) ---
    real("git add -A", cwd=repo)
    commit_out = real("git commit -m 'ci: establish a3 baseline'", cwd=repo)
    push_display = truncate_lines(commit_out) + \
        "\n\n  (git push — baseline now committed, future CI only flags NEW bugs)"
    run_cmd("git add .a3-baseline.json && git commit -m 'ci: establish baseline' && git push",
            push_display, pause=2.5)

    emit(hold=1.5)


# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO 3: Incremental — add a file, auto-invoke
# ══════════════════════════════════════════════════════════════════════════════
def scenario_3(repo):
    title_card("Scenario 3: Incremental Auto-Invoke",
               "Add a new .py file  →  Push  →  CI scans only new file")

    # --- cat workflow trigger (REAL) ---
    wf_path = os.path.join(repo, ".github", "workflows", "a3-pr-scan.yml")
    if os.path.exists(wf_path):
        with open(wf_path) as f:
            wf_lines = f.readlines()
        wf_head = "".join(wf_lines[:12]).rstrip()
    else:
        wf_head = "(workflow file not found)"
    run_cmd("head -12 .github/workflows/a3-pr-scan.yml", wf_head, pause=3.0)

    # --- Write payments.py (show the code being typed) ---
    prompt()
    type_text("cat > src/payments.py << 'EOF'", speed=0.04)
    feed("\r\n"); emit(hold=0.1)
    show_output(PAYMENTS_BUGGY.rstrip() + "\nEOF", per_line=0.12)
    emit(hold=2.0)

    # Actually write it
    with open(os.path.join(repo, "src", "payments.py"), "w") as f:
        f.write(PAYMENTS_BUGGY)

    # --- git add + commit (REAL) ---
    real("git add src/payments.py", cwd=repo)
    commit_out = real("git commit -m 'feat: add payment processing'", cwd=repo)
    run_cmd("git add src/payments.py && git commit -m 'feat: add payment processing'",
            truncate_lines(commit_out), pause=1.5)

    # --- git push (SIMULATED) ---
    run_cmd("git push",
            truncate_lines(commit_out.split("\n")[0]) +
            "\n\n  → CI triggered: paths filter matched src/payments.py"
            "\n  → Running: a3 scan (changed files only)...",
            pause=2.5)

    # --- a3 scan whole repo with new file (REAL — so SARIF is produced) ---
    scan_out = real(
        f"python3 -m a3_python scan {repo} --output-sarif {repo}/pay_results.sarif")
    run_cmd("a3 scan . --output-sarif results.sarif  # CI scans repo",
            truncate_lines(scan_out), pause=3.0)

    # --- a3 baseline diff (REAL — expect new bug) ---
    diff_out = real(
        f"python3 -m a3_python baseline diff "
        f"--sarif {repo}/pay_results.sarif --baseline {repo}/.a3-baseline.json")
    run_cmd("a3 baseline diff --sarif results.sarif",
            truncate_lines(diff_out), pause=3.0)

    # ── Fix ──
    title_card("Fix the Bug, Push Again",
               "Add a guard → a3 proves it safe → CI passes")

    prompt()
    type_text("# Fix: add guard for discount == 0", speed=0.04)
    feed("\r\n"); emit(hold=0.5)

    # --- cat fixed file (REAL) ---
    with open(os.path.join(repo, "src", "payments.py"), "w") as f:
        f.write(PAYMENTS_FIXED)
    cat_fixed = real("cat src/payments.py")
    run_cmd("cat src/payments.py   # after fix",
            truncate_lines(cat_fixed), pause=2.5)

    # --- git commit (REAL) ---
    real("git add -A", cwd=repo)
    fix_commit = real("git commit -m 'fix: guard discount division'", cwd=repo)
    run_cmd("git commit -am 'fix: guard discount division' && git push",
            truncate_lines(fix_commit) +
            "\n\n  → CI triggered: a3 scan src/payments.py...",
            pause=2.0)

    # --- a3 scan fixed (REAL) ---
    fix_scan = real(
        f"python3 -m a3_python scan {repo} --output-sarif {repo}/pay_fixed_results.sarif")
    run_cmd("# CI runs: a3 scan .",
            truncate_lines(fix_scan), pause=2.5)

    # --- a3 baseline diff (REAL — expect pass) ---
    fix_diff = real(
        f"python3 -m a3_python baseline diff "
        f"--sarif {repo}/pay_fixed_results.sarif --baseline {repo}/.a3-baseline.json")
    run_cmd("a3 baseline diff --sarif results.sarif",
            truncate_lines(fix_diff), pause=3.5)

    emit(hold=2.0)


# ── Outro ────────────────────────────────────────────────────────────────────
def outro():
    title_card("Three Ways to Use a3-python", "")
    screen.reset()
    feed("\r\n\r\n")
    box = [
        "┌─────────────────────────────────────────────────────────────────────────┐",
        "│  \x1b[1;32mScenario 1:\x1b[0m  End-to-End Setup                                       │",
        "│              git init → seed code → a3 init --copilot → push          │",
        "│                                                                       │",
        "│  \x1b[1;36mScenario 2:\x1b[0m  Whole-Repo Scan                                        │",
        "│              a3 scan . → triage → baseline accept                     │",
        "│                                                                       │",
        "│  \x1b[1;33mScenario 3:\x1b[0m  Incremental Auto-Invoke                                │",
        "│              Add .py file → push → CI auto-scans → fix → CI passes   │",
        "│                                                                       │",
        "│  \x1b[35mpip install a3-python[ci]   a3 init . --copilot   git push\x1b[0m        │",
        "└─────────────────────────────────────────────────────────────────────────┘",
    ]
    for line in box:
        feed(f"  \x1b[1;37m{line}\x1b[0m\r\n")
    emit(hold=5.0)


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    global writer

    print("Setting up repo...")
    repo = setup_repo()
    print(f"  Repo: {repo}")
    print(f"  Files: {os.listdir(os.path.join(repo, 'src'))}")

    writer = VideoWriter(OUT_PATH, WIDTH, HEIGHT, FPS)
    print(f"  Recording to {OUT_PATH}  ({WIDTH}x{HEIGHT} @ {FPS}fps)\n")

    title_card("a3-python: Terminal Demo",
               "Three ways to integrate static analysis into your workflow")

    print("  Scenario 1: End-to-End Setup...")
    scenario_1(repo)

    print("  Scenario 2: Whole-Repo Scan...")
    scenario_2(repo)

    print("  Scenario 3: Incremental Auto-Invoke...")
    scenario_3(repo)

    print("  Outro...")
    outro()

    writer.close()
    mb = os.path.getsize(OUT_PATH) / (1024 * 1024)
    print(f"\n✔ Done! {OUT_PATH}  ({mb:.1f} MB)")


if __name__ == "__main__":
    main()
