#!/bin/bash -ex

for host in check-tls.akamaized.net \
		cloudflare-esni.com \
		cloudflareresearch.com \
		crypto.cloudflare.com \
		deb.debian.org \
		duckduckgo.com \
		en.wikipedia.org \
		enabled.tls13.com \
		mirrors.kernel.org \
		openstreetmap.org \
		tls13.1d.pw \
		web.wechat.com \
		www.google.com \
		www.yandex.ru \
	    ; do
    ECH=`dig +short -t TYPE65 $host | \
        tail -1 | cut -f 3- -d' ' | sed -e 's/ //g' | sed -e 'N;s/\n//'`
    if [[ "$ECH" == "" ]]; then
        echo "Can't read HTTPS/TYPE65 for $host"
    else
	echo $ECH | xxd -p -r > openjdk/src/test/resources/${host}.bin
    fi
done
