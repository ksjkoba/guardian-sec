#!/usr/bin/env bash
# Guardian one-shot setup script

set -e

echo "=== Guardian Setup ==="
echo ""

# 1. Check Python
python3 --version || { echo "ERROR: Python 3.10+ required"; exit 1; }

# 2. Create venv
if [ ! -d ".venv" ]; then
    echo "[1/4] Creating virtual environment..."
    python3 -m venv .venv
fi

source .venv/bin/activate

# 3. Install core deps
echo "[2/4] Installing core dependencies..."
pip install -q --upgrade pip
pip install -q click rich psutil

# 4. Install llama-cpp-python
echo "[3/4] Installing llama-cpp-python (CPU build)..."
echo "      For GPU support see: https://github.com/abetlen/llama-cpp-python"
pip install -q llama-cpp-python

# 5. Install guardian
echo "[4/4] Installing Guardian..."
pip install -q -e .

echo ""
echo "=== Setup complete ==="
echo ""
echo "Next step: download the model"
echo "  guardian download-model"
echo ""
echo "Then start defending:"
echo "  guardian defend"
echo "  guardian scan-code /path/to/your/project"
echo "  guardian watch-logs"
