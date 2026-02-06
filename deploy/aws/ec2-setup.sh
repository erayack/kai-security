#!/bin/bash
# EC2 Setup Script for Kai
# Run this on the EC2 instance after SSHing in

set -e

echo "=========================================="
echo "Kai EC2 Setup Script"
echo "=========================================="

# Update system
echo "[1/6] Updating system packages..."
sudo yum update -y

# Install Python 3.11+ (Amazon Linux 2023 has it, AL2 needs extra repo)
echo "[2/6] Installing Python..."
sudo yum install -y python3.11 python3.11-pip python3.11-devel git

# Install build dependencies
echo "[3/6] Installing build dependencies..."
sudo yum groupinstall -y "Development Tools"
sudo yum install -y openssl-devel bzip2-devel libffi-devel

# Install Foundry
echo "[4/6] Installing Foundry (Solidity toolchain)..."
curl -L https://foundry.paradigm.xyz | bash
source ~/.bashrc
~/.foundry/bin/foundryup

# Add Foundry to PATH permanently
echo 'export PATH="$HOME/.foundry/bin:$PATH"' >> ~/.bashrc
export PATH="$HOME/.foundry/bin:$PATH"

# Verify Foundry
echo "Foundry version:"
forge --version

# Clone the repo
echo "[5/6] Cloning exploit-agent repository..."
cd ~
if [ -d "exploit-agent" ]; then
    echo "Repository already exists, pulling latest..."
    cd exploit-agent && git pull
else
    git clone https://github.com/firstbatchxyz/exploit-agent.git
    cd exploit-agent
fi

# Setup Python environment
echo "[6/6] Setting up Python environment..."
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .

echo ""
echo "=========================================="
echo "Setup complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Set your API key:"
echo "   export OPENROUTER_API_KEY='sk-or-v1-your-key'"
echo ""
echo "2. (Optional) Set MongoDB URI:"
echo "   export MONGO_URI='mongodb+srv://...'"
echo ""
echo "3. Run Kai in tmux:"
echo "   tmux new -s kai"
echo "   source .venv/bin/activate"
echo "   python scripts/batch_cantina_runner.py --limit 2"
echo ""
echo "4. Detach tmux: Ctrl+B, then D"
echo "5. Reattach later: tmux attach -t kai"
