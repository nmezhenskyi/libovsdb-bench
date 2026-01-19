#!/bin/bash
set -e

BINARY_NAME="ovsdb"
ITERATIONS=100
PREFIX="bench_test"
LOG_CLI="result_cli.log"
LOG_LIB="result_lib.log"

echo -e "[INFO] Compiling Go binary..."
if ! go build -o "${BINARY_NAME}" ./; then
    echo "Error: Failed to build"
    exit 1
fi

cleanup_ovn() {
    echo -ne "[INFO] Cleaning up OVN environment..."
    
    # List all Logical Switches starting with our prefix and delete them.
    # Use --format=csv to get clean names without table borders.
    local targets
    targets=$(ovn-nbctl --format=csv --no-heading --columns=name list Logical_Switch | grep "^${PREFIX}" || true)

    if [ -n "$targets" ]; then
        echo "$targets" | xargs -r -n1 ovn-nbctl ls-del >/dev/null 2>&1
    fi
    echo "Done."
}

cleanup_ovn
echo -e "\n[TEST 1/2] Running OVN-NBCTL Benchmark (${ITERATIONS} iters)..."
./"${BINARY_NAME}" -mode cli -count "${ITERATIONS}" 2>&1 | tee "${LOG_CLI}"

cleanup_ovn
echo -e "\n[TEST 2/2] Running Libovsdb Benchmark (${ITERATIONS} iters)..."
./"${BINARY_NAME}" -mode lib -count "${ITERATIONS}" 2>&1 | tee "${LOG_LIB}"

cleanup_ovn

echo -e "\n================================================="
echo -e "             FINAL RESULTS SUMMARY               "
echo -e "================================================="

extract_stat() {
    local file=$1
    local search_term=$2 
    
    grep "$search_term" "$file" | tail -n 1 | awk '{print $NF}'
}

# 1. Extract Time and Latency
CLI_TOTAL=$(grep "Total Time:" "$LOG_CLI" | tail -n 1 | awk '{print $NF}')
CLI_AVG=$(grep "Avg Latency:" "$LOG_CLI" | tail -n 1 | awk '{print $NF}')

LIB_TOTAL=$(grep "Total Time:" "$LOG_LIB" | tail -n 1 | awk '{print $NF}')
LIB_AVG=$(grep "Avg Latency:" "$LOG_LIB" | tail -n 1 | awk '{print $NF}')

# 2. Extract Throughput
CLI_OPS=$(grep "Throughput:" "$LOG_CLI" | tail -n 1 | awk '{print $(NF-1)}')
LIB_OPS=$(grep "Throughput:" "$LOG_LIB" | tail -n 1 | awk '{print $(NF-1)}')

# Print Table
printf "%-20s | %-15s | %-15s\n" "Metric" "ovn-nbctl" "libovsdb"
echo "--------------------------------------------------------"
printf "%-20s | %-15s | %-15s\n" "Total Time" "$CLI_TOTAL" "$LIB_TOTAL"
printf "%-20s | %-15s | %-15s\n" "Average Latency" "$CLI_AVG" "$LIB_AVG"
printf "%-20s | %-15s | %-15s\n" "Throughput" "$CLI_OPS" "$LIB_OPS"
echo "--------------------------------------------------------"
