#!/bin/bash
# build.sh — compile the paper (and supplement) and enforce the 13-page TIFS limit.
# Usage: bash build.sh [main|supp|all]   (default: all)
# Output goes to build/ so the committed PDFs are only replaced on success.
set -e
cd "$(dirname "$0")"
mkdir -p build
python3 make_numbers.py   # numbers.tex from the result JSONs; fails on a missing file or key

compile() {
    local doc=$1
    pdflatex -interaction=nonstopmode -halt-on-error -output-directory=build "$doc.tex" > "build/$doc.pass1.log" || { tail -30 "build/$doc.log"; exit 1; }
    if grep -q '\\bibdata' "build/$doc.aux"; then
        (cp References.bib IEEETran.bst build/ 2>/dev/null; cd build && bibtex "$doc" > "$doc.bibtex.log") || { cat "build/$doc.bibtex.log"; exit 1; }
    fi
    pdflatex -interaction=nonstopmode -halt-on-error -output-directory=build "$doc.tex" > /dev/null
    pdflatex -interaction=nonstopmode -halt-on-error -output-directory=build "$doc.tex" > /dev/null
    grep -E "Warning: (Reference|Citation).*undefined" "build/$doc.log" | sort -u | head -10 || true
}

case "${1:-all}" in
    main) compile ieee-paper ;;
    supp) compile supplementary-material ;;
    all)  compile ieee-paper; compile supplementary-material ;;
esac

node pagecount.js build/ieee-paper.pdf 13
[ -f build/supplementary-material.pdf ] && node pagecount.js build/supplementary-material.pdf 99 || true
