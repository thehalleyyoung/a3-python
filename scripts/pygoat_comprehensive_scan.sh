#!/bin/bash
# Comprehensive PyGoat scan to understand security bug detection status

echo "==================================================================="
echo "PyGoat Security Bug Detection - Iteration 251"
echo "==================================================================="
echo ""

# Scan key files
for file in \
    "external_tools/pygoat/introduction/views.py" \
    "external_tools/pygoat/introduction/apis.py" \
    "external_tools/pygoat/challenge/views.py" \
    "external_tools/pygoat/dockerized_labs/broken_auth_lab/app.py"
do
    if [ -f "$file" ]; then
        echo ">>> Scanning: $file"
        python3 -m pyfromscratch.cli "$file" --functions 2>&1 | \
            grep -E "(PATH_INJECTION|CODE_INJECTION|SQL_INJECTION|COMMAND_INJECTION|FULL_SSRF|cmd_lab2:|ssrf_lab:|sql_lab:|Function-level entry points)" | \
            head -20
        echo ""
    fi
done

echo "==================================================================="
echo "Summary of Security Bugs Found"
echo "==================================================================="
