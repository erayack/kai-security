#!/bin/bash

set -e  # Exit on any error

echo "════════════════════════════════════════════════════════════════"
echo "  Exploit Agent - Complete Installation"
echo "════════════════════════════════════════════════════════════════"
echo ""

# 1. Check and install uv
echo "📦 Checking for uv..."
if ! command -v uv > /dev/null 2>&1; then
    echo "   uv not found. Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # Source the uv path for this script
    export PATH="$HOME/.local/bin:$PATH"
else
    echo "   ✓ uv is already installed ($(uv --version))"
fi
echo ""

# 2. Install Python dependencies
echo "🐍 Installing Python dependencies with uv..."
uv sync
echo "   ✓ Python dependencies installed"
echo ""

# 3. Check and install foundry
if ! command -v forge > /dev/null 2>&1 && ! [ -f "$HOME/.foundry/bin/forge" ]; then
    echo "🔨 Installing Foundry..."
    
    # macOS-specific: check for libusb
    if [ "$(uname)" = "Darwin" ]; then
        echo "   Detected macOS. Checking for libusb..."
        if ! brew list libusb > /dev/null 2>&1; then
            echo "   libusb not found. Installing via Homebrew..."
            if ! command -v brew > /dev/null; then
                echo ""
                echo "✗ Error: Homebrew is not installed."
                echo "  Please install Homebrew first:"
                echo "  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
                exit 1
            fi
            brew install libusb
        else
            echo "   ✓ libusb is already installed"
        fi
    fi
    
    # Install foundryup if not present
    if ! command -v foundryup > /dev/null 2>&1 && ! [ -f "$HOME/.foundry/bin/foundryup" ]; then
        echo "   Installing foundryup..."
        curl -L https://foundry.paradigm.xyz | bash
    fi
    
    # Run foundryup to install Foundry toolchain
    echo "   Installing Foundry toolchain (forge, cast, anvil, chisel)..."
    if command -v foundryup > /dev/null 2>&1; then
        foundryup
    elif [ -f "$HOME/.foundry/bin/foundryup" ]; then
        "$HOME/.foundry/bin/foundryup"
    else
        echo ""
        echo "✗ Error: foundryup installation failed"
        exit 1
    fi
    
    # Verify installation
    if [ -f "$HOME/.foundry/bin/forge" ]; then
        echo "   ✓ Foundry installed successfully!"
    else
        echo ""
        echo "✗ Error: Foundry installation failed"
        exit 1
    fi
    echo ""
elif [ -f "$HOME/.foundry/bin/forge" ]; then
    echo "🔨 Foundry is already installed"
    echo ""
fi

# 4. Final status check
echo "════════════════════════════════════════════════════════════════"
echo "  Installation Complete! ✓"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Check if forge is in PATH
if command -v forge > /dev/null 2>&1; then
    echo "✓ All tools are ready to use!"
    echo ""
    echo "Installed versions:"
    echo "  • uv: $(uv --version)"
    echo "  • forge: $(forge --version | head -n 1)"
else
    echo "✓ All tools are installed!"
    echo ""
    echo "⚡ To use Foundry tools NOW in THIS terminal:"
    echo ""
    echo "   export PATH=\"\$HOME/.foundry/bin:\$PATH\""
    echo ""
    echo "Or simply open a NEW terminal (PATH is already configured)."
fi
echo ""
