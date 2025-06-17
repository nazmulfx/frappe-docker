#!/bin/bash

echo "Testing Mixed HTTP/HTTPS Setup"
echo "=============================="
echo ""

# Check if Traefik is running
if ! docker ps | grep -q traefik; then
    echo "❌ Traefik is not running"
    exit 1
fi

echo "✅ Traefik is running"

# Check Traefik ports
TRAEFIK_PORTS=$(docker ps --format "{{.Ports}}" --filter "name=traefik")
echo "Traefik ports: $TRAEFIK_PORTS"

if [[ $TRAEFIK_PORTS == *":80->80"* ]]; then
    echo "✅ Port 80 (HTTP) is exposed"
else
    echo "❌ Port 80 (HTTP) is NOT exposed"
fi

if [[ $TRAEFIK_PORTS == *":443->443"* ]]; then
    echo "✅ Port 443 (HTTPS) is exposed"
else
    echo "❌ Port 443 (HTTPS) is NOT exposed"
fi

echo ""
echo "Checking Traefik configuration..."

# Check if Traefik has both entrypoints
WEB_ENTRYPOINT=$(docker logs traefik 2>&1 | grep -c "entrypoint web")
WEBSECURE_ENTRYPOINT=$(docker logs traefik 2>&1 | grep -c "entrypoint websecure")

if [[ $WEB_ENTRYPOINT -gt 0 ]]; then
    echo "✅ Web entrypoint (HTTP) is configured"
else
    echo "❌ Web entrypoint (HTTP) is NOT configured"
fi

if [[ $WEBSECURE_ENTRYPOINT -gt 0 ]]; then
    echo "✅ Websecure entrypoint (HTTPS) is configured"
else
    echo "❌ Websecure entrypoint (HTTPS) is NOT configured"
fi

echo ""
echo "Checking for global HTTP to HTTPS redirects..."
GLOBAL_REDIRECT=$(docker inspect traefik | grep -c "entrypoints.web.http.redirections")

if [[ $GLOBAL_REDIRECT -gt 0 ]]; then
    echo "⚠️  Global HTTP to HTTPS redirect is enabled"
    echo "   This will break HTTP-only domains!"
    echo "   Run: ./fix_mixed_http_https.sh to fix this"
else
    echo "✅ No global HTTP to HTTPS redirect found"
    echo "   Mixed HTTP/HTTPS setup should work correctly"
fi

echo ""
echo "Current running sites:"
docker ps --format "table {{.Names}}\t{{.Status}}" | grep frontend

echo ""
echo "Summary:"
echo "========"

BOTH_PORTS=$([[ $TRAEFIK_PORTS == *":80->80"* ]] && [[ $TRAEFIK_PORTS == *":443->443"* ]] && echo "true" || echo "false")
NO_GLOBAL_REDIRECT=$([[ $GLOBAL_REDIRECT -eq 0 ]] && echo "true" || echo "false")

if [[ "$BOTH_PORTS" == "true" ]] && [[ "$NO_GLOBAL_REDIRECT" == "true" ]]; then
    echo "✅ Mixed HTTP/HTTPS setup is WORKING correctly"
    echo "   - HTTP-only domains will work on port 80"
    echo "   - HTTPS domains will work on port 443 with SSL"
else
    echo "❌ Mixed HTTP/HTTPS setup has ISSUES"
    if [[ "$BOTH_PORTS" == "false" ]]; then
        echo "   - Missing port configuration in Traefik"
        echo "   - Run: ./fix_traefik_https.sh to fix"
    fi
    if [[ "$NO_GLOBAL_REDIRECT" == "false" ]]; then
        echo "   - Global HTTP redirect is breaking HTTP-only domains"
        echo "   - Run: ./fix_mixed_http_https.sh to fix"
    fi
fi 