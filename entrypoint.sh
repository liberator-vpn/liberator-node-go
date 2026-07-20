#!/bin/sh
set -e

# Включаем IP-форвардинг на хосте (требует NET_ADMIN)
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true

# Запускаем Go‑приложение, передавая ему все аргументы командной строки
exec /usr/local/bin/vpn-router "$@"