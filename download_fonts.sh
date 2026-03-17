#!/bin/bash
FONT_DIR=~/Documents/WORKSPACE/wavs2026/public/fonts
mkdir -p "$FONT_DIR"

echo "Downloading DM Sans..."
wget -q "https://fonts.gstatic.com/s/dmsans/v15/rP2Hp2ywxg089UriCZOIHQ.woff2" -O "$FONT_DIR/DM-Sans-300.woff2"
wget -q "https://fonts.gstatic.com/s/dmsans/v15/rP2Hp2ywxg089UriCZOIHQ.woff2" -O "$FONT_DIR/DM-Sans-400.woff2"
wget -q "https://fonts.gstatic.com/s/dmsans/v15/rP2Hp2ywxg089UriCZOIHQ.woff2" -O "$FONT_DIR/DM-Sans-500.woff2"
wget -q "https://fonts.gstatic.com/s/dmsans/v15/rP2Hp2ywxg089UriCZOIHQ.woff2" -O "$FONT_DIR/DM-Sans-600.woff2"
wget -q "https://fonts.gstatic.com/s/dmsans/v15/rP2Hp2ywxg089UriCZOIHQ.woff2" -O "$FONT_DIR/DM-Sans-700.woff2"

echo "Downloading DM Mono..."
wget -q "https://fonts.gstatic.com/s/dmmono/v14/aFTU7PB1QTsUX8KYvrumzvg.woff2" -O "$FONT_DIR/DM-Mono-300.woff2"
wget -q "https://fonts.gstatic.com/s/dmmono/v14/aFTU7PB1QTsUX8KYvrumzvg.woff2" -O "$FONT_DIR/DM-Mono-400.woff2"
wget -q "https://fonts.gstatic.com/s/dmmono/v14/aFTU7PB1QTsUX8KYvrumzvg.woff2" -O "$FONT_DIR/DM-Mono-500.woff2"

echo "✅ Done"
ls -lh "$FONT_DIR"
