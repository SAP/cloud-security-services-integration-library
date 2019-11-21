#!/bin/bash
#set -x 
 
if [ "$1" ]; then
        cp $1 sk.tmp.sk
        cat $1 | jq --raw-output '.key' > key.pem
 
        cat $1 | jq --raw-output '.certificate' > certificate.pem
        export URL=`cat $1 | jq --raw-output .url`
        export URL=`echo $URL | sed 's/.authentication./.authentication.cert./g'`
        export CLIENTID=`cat $1 | jq --raw-output '.clientid'`
        echo "keys extracted to certificate.pem and key.pem"
        echo
        echo "curl to obtain a token:"
        echo curl  --cert certificate.pem --key key.pem  -XPOST $URL/oauth/token -d "'grant_type=client_x509&client_id="$CLIENTID"'"
else
        echo "call $0 <path to service-key json>"
fi
