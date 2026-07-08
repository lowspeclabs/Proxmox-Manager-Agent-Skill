#!/bin/bash
set -euo pipefail

VMID="${1:-}"

if [[ -z "$VMID" ]]; then
    echo "Usage: $0 <vmid>"
    exit 1
fi

if ! pct status "$VMID" >/dev/null 2>&1; then
    echo "Error: container $VMID does not exist"
    exit 1
fi

STATUS=$(pct status "$VMID" | grep "^status:" | cut -d" " -f2)
if [[ "$STATUS" != "running" ]]; then
    echo "Starting container $VMID ..."
    pct start "$VMID"
    sleep 2
fi

echo "Applying console-getty and container-getty fixes to container $VMID ..."

pct exec "$VMID" -- mkdir -p /etc/systemd/system/console-getty.service.d
pct exec "$VMID" -- sh -c 'printf "[Service]\nImportCredential=\n" > /etc/systemd/system/console-getty.service.d/override.conf'
pct exec "$VMID" -- mkdir -p /etc/systemd/system/container-getty@.service.d
pct exec "$VMID" -- sh -c 'printf "[Service]\nImportCredential=\n" > /etc/systemd/system/container-getty@.service.d/override.conf'
pct exec "$VMID" -- systemctl daemon-reload
pct exec "$VMID" -- systemctl reset-failed console-getty.service container-getty@1.service container-getty@2.service || true
pct exec "$VMID" -- systemctl start console-getty.service container-getty@1.service container-getty@2.service

echo "Verifying getty services ..."
for svc in console-getty.service container-getty@1.service container-getty@2.service; do
    if pct exec "$VMID" -- systemctl is-active --quiet "$svc"; then
        echo "Success: $svc is active on container $VMID"
    else
        echo "Error: $svc failed to start on container $VMID"
        pct exec "$VMID" -- systemctl status "$svc" --no-pager
        exit 1
    fi
done
