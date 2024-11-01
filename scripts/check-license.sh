FILE_GLOB=$1

LICENSE_BODY_FILE="scripts/license-header.txt"
LICENSE_LINES=$(wc -l $LICENSE_BODY_FILE | xargs | cut -f1 -d ' ')

echo "License text from '$LICENSE_BODY_FILE' has $LICENSE_LINES lines"

rc=0
counter_failed=0
counter_all=0

for x in $FILE_GLOB; do  

    counter_all=$((counter_all+1))

    if [ -f "$x" ]; then
        # echo "Checking $x"
        head -$LICENSE_LINES $x | diff $LICENSE_BODY_FILE - || {
            rc=1;
            counter_failed=$((counter_failed+1))
            echo "ERROR: License header not found in $x\n"
        }
    else
        echo "Skipping $x"
    fi
done

if [ $rc -eq 1 ]; then
    echo "ERROR: $counter_failed out of $counter_all files lack a license header"
else
    echo "All $counter_all files have a license header"
fi

exit $rc
