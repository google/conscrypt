#!/bin/bash -ex

defohost=draft-13.esni.defo.ie
for defoport in 8413 8414 9413 10413 11413 12413 12414; do
    ECH=`dig +short -t TYPE65 "_$defoport._https.$defohost" | \
        tail -1 | cut -f 3- -d' ' | sed -e 's/ //g' | sed -e 'N;s/\n//'`
    if [[ "$ECH" == "" ]]
    then
        echo "Can't read ECHConfigList for $defohost:$defoport"
        exit 2
    fi
    ah_ech=${ECH:14}
    echo $ah_ech | xxd -p -r > openjdk/src/test/resources/${defohost}_${defoport}-ech-config-list.bin
done
