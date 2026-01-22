#!/bin/bash

FILE="/etc/ppp/chap-secrets"
LAST_HASH=""

while true; do
    if [ -f "$FILE" ]; then
        CURRENT_HASH=$(md5sum "$FILE" 2>/dev/null | awk '{print $1}')
        
        if [ -n "$LAST_HASH" ] && [ "$CURRENT_HASH" != "$LAST_HASH" ]; then
            echo "$(date): $FILE has changed!"
            # Add your action here
            logger "chap-secrets file changed"
	    systemctl restart strongswan-starter xl2tpd&
	    echo "restart l2tp/ipsec vpn service"

        fi
        
        LAST_HASH="$CURRENT_HASH"
    else
        echo "$(date): $FILE does not exist"
    fi
    
    sleep 300
done
