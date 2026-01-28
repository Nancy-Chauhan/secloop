#!/bin/bash

# Ralph Loop - Dependency Vulnerability Patcher
# Runs Claude in a loop until vulnerabilities are fixed

set -e

# Configuration
MAX_ITERATIONS=10
PROMPT_FILE="PROMPT.md"
OUTPUT_DIR="output"
COMPLETION_TOKEN="<COMPLETE>"
PROJECT_DIR="sample_project"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Setup virtual environment if it doesn't exist
setup_venv() {
    if [ ! -d "$PROJECT_DIR/venv" ]; then
        echo -e "${YELLOW}Setting up virtual environment...${NC}"
        python3 -m venv "$PROJECT_DIR/venv"
        source "$PROJECT_DIR/venv/bin/activate"
        pip install --upgrade pip
        pip install pip-audit pytest
        pip install -r "$PROJECT_DIR/requirements.txt"
    else
        source "$PROJECT_DIR/venv/bin/activate"
    fi
}

# Run initial vulnerability scan for context
initial_scan() {
    echo -e "${YELLOW}Running initial vulnerability scan...${NC}"
    cd "$PROJECT_DIR"
    pip-audit 2>&1 | tee "../$OUTPUT_DIR/initial_scan.txt" || true
    cd ..
    echo ""
}

# Main loop
main() {
    echo -e "${GREEN}=== Ralph Loop: Dependency Vulnerability Patcher ===${NC}"
    echo "Max iterations: $MAX_ITERATIONS"
    echo ""

    setup_venv
    initial_scan

    for i in $(seq 1 $MAX_ITERATIONS); do
        echo -e "${YELLOW}=== Iteration $i of $MAX_ITERATIONS ===${NC}"

        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        OUTPUT_FILE="$OUTPUT_DIR/iteration_${i}_${TIMESTAMP}.txt"

        # Run Claude with the prompt
        # Using --dangerously-skip-permissions for autonomous operation
        # In production, configure proper permissions instead
        if command -v claude &> /dev/null; then
            cat "$PROMPT_FILE" | claude --dangerously-skip-permissions 2>&1 | tee "$OUTPUT_FILE"
        else
            echo -e "${RED}Error: 'claude' CLI not found. Install Claude Code first.${NC}"
            echo "Visit: https://docs.anthropic.com/claude-code"
            exit 1
        fi

        # Check for completion token
        if grep -q "$COMPLETION_TOKEN" "$OUTPUT_FILE"; then
            echo ""
            echo -e "${GREEN}=== SUCCESS ===${NC}"
            echo "Completed in $i iteration(s)"
            echo "Output saved to: $OUTPUT_FILE"

            # Final verification
            echo ""
            echo -e "${YELLOW}Final verification:${NC}"
            cd "$PROJECT_DIR"
            echo "--- pip-audit ---"
            pip-audit || true
            echo ""
            echo "--- pytest ---"
            pytest -v || true
            cd ..

            exit 0
        fi

        echo ""
        echo -e "${YELLOW}Completion token not found. Continuing loop...${NC}"
        echo ""
        sleep 2
    done

    echo ""
    echo -e "${RED}=== MAX ITERATIONS REACHED ===${NC}"
    echo "The loop did not complete within $MAX_ITERATIONS iterations."
    echo "Review the output files in $OUTPUT_DIR for details."
    exit 1
}

# Run
main "$@"
