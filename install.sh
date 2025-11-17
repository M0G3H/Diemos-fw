#!/bin/bash

# Display the banner
echo " ________  ___  _______   _____ ______   ________  ________                 ________ ___       __      "
echo "|\   ___ \|\  \|\  ___ \ |\   _ \  _   \|\   __  \|\   ____\               |\  _____\\  \     |\  \    "
echo "\ \  \_|\ \ \  \ \   __/|\ \  \\\\__\ \  \ \  \|\  \ \  \___|_  ____________\ \  \__/\ \  \    \ \  \   "
echo " \ \  \\ \\ \ \  \ \  \_|/_\ \  \\|__| \  \ \  \\\\  \ \_____  \|\____________\ \   __\\ \  \  __\ \  \  "
echo "  \ \  \\_\\ \ \  \ \  \_|\ \ \  \    \ \  \ \  \\\\  \|____|\  \|____________| \ \  \_| \ \  \|\__\_\  \ "
echo "   \ \_______\\ \__\ \_______\\ \__\    \ \__\ \_______\\____\_\  \              \ \__\   \ \____________\\"
echo "    \|_______|\|__|\|_______|\|__|     \|__|\|_______|\_________\              \|__|    \|____________|"
echo "                                                     \|_________|                                      "
echo ""


# Extract Go version from go.mod
GO_MOD_VERSION=$(grep '^go ' go.mod | awk '{print $2}')
if [ -z "$GO_MOD_VERSION" ]; then
    echo "❌ Error: Could not find Go version in go.mod"
    echo "Make sure go.mod has a line like: go 1.21"
    exit 1
fi

echo "📋 Go version required by go.mod: $GO_MOD_VERSION"

# Check installed Go version
INSTALLED_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
if [ -z "$INSTALLED_GO_VERSION" ]; then
    echo "❌ Error: Go is not installed or not in PATH"
    exit 1
fi

echo "🔍 Installed Go version: $INSTALLED_GO_VERSION"

# Compare versions (simple string comparison - for more complex version checking you might need a different approach)
if [ "$INSTALLED_GO_VERSION" != "$GO_MOD_VERSION" ]; then
    echo "❌ Error: Go version mismatch!"
    echo "Required: $GO_MOD_VERSION, Found: $INSTALLED_GO_VERSION"
    echo "Please install Go version $GO_MOD_VERSION"
    exit 1
fi

echo "✅ Go version matches requirements"

# Build the project
echo "🔨 Building Diemos-fw..."
if ! go build -o Diemos-fw .; then
    echo "❌ Error: Build failed!"
    exit 1
fi

echo "✅ Build successful"

# Install to /usr/local/bin
echo "📥 Installing Diemos-fw to /usr/local/bin..."
if ! sudo install -m 755 Diemos-fw /usr/local/bin/; then
    echo "❌ Error: Installation failed!"
    exit 1
fi

echo "✅ Installation successful"

# Verify installation
echo "🔍 Verifying installation..."
if ! Diemos-fw --version; then
    echo "❌ Error: Could not verify installation"
    exit 1
fi

echo ""
echo "🎉 Diemos-fw has been successfully installed!"
echo "You can now run 'Diemos-fw' from anywhere in your terminal"
