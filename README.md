# liberator-node-go

VPN-шлюз (egress/ingress нода) в распределённой сети Liberator. Нода —
**полностью пассивный** компонент: у неё нет inbound control-plane (кроме
`/healthz` и `/metrics`), она сама ходит в контроль-плоскость (`liberator-api`)
и применяет желаемое состояние.

## Что делает нода
- Поднимает overlay: TUN-интерфейс + NAT в интернет, AmneziaWG-приём клиентов.
- Опционально поднимает **VLESS+REALITY** и **Hysteria2** через внешний
  `xray-core` (`router.transports.<name>.type: xray`). Xray терминирует
  клиентские протоколы, отдаёт расшифрованный IP-трафик в отдельный
  `proxy_tun`, а нода забирает его в общий роутер — поэтому firewall,
  policy-egress, шейпер, учёт трафика и client→client через mesh работают
  одинаково для всех протоколов.
- Для proxy-протоколов каждому пользователю выдаётся локальный `local_ip` из
  `local_cidr`; он назначается на dummy-интерфейс, а policy-routing
  (`ip rule`/`ip route`) направляет пакеты с него в `proxy_tun`. Xray получает
  `freedom`-outbound с `sendThrough=<local_ip>`. Нода переписывает
  `local_ip → virtual_ip` на входе и `virtual_ip → local_ip` на выходе, поэтому
  трафик проходит через общий роутер: работают firewall, шейпер, учёт байт,
  policy-egress и mesh. `virtual_ip` пользователя при этом не назначается на хост.
- Держит **QUIC-пул** к остальным нодам (общий `auth.secret_key`, список соседей
  из `mesh.dns_service`/`mesh.static`).
- По контракту `/v1/node` с API:
  - enroll по одноразовому токену (`/v1/node/enroll`) и получает `node_id`, per-node secret, `gateway_addr`;
  - шлёт `heartbeat`;
  - тянет желаемое состояние (`/state`) и **реконсилит** локальных клиентов
    (создание/обновление/удаление awg-пиров по `peer_ip`+`client_public_key`,
    лимиты из квот);
  - применяет **firewall-pairs** (`/state.firewall_pairs`) — разрешённые
    client→client потоки по IP-парам (enforcement на источнике);
  - тянет глобальную директорию клиентов (`/v1/node/clients`) и ставит **remote-маршруты**:
    клиент другой ноды → пересылка датаграмм через QUIC-пул на её `mesh_endpoint`
    (client→client);
  - применяет **policy-egress** из `/state.egress` (`{peer_ip, prefix, exit_mesh_endpoint}`):
    интернет-dst клиента, попавший под prefix, форвардится на ноду-выход (она NATит);
    не совпало ни с одним правилом — локальный NAT;
  - подтверждает активацию сессий (`sessions/activate`, `issued → active`);
  - пушит дельты трафика по сессиям (`nodes/usage`, billing).
- Отдаёт метрики Prometheus (`node_traffic_bytes_total`, `node_packet_lifetime_seconds`,
  счётчики клиентов/пула) на `/metrics`.

Нода ничего не аллоцирует и не хранит в БД: `peer_ip` клиентам и `gateway_addr`
ноде выдаёт API из общего overlay-пула.

### Proxy-протоколы и control-plane

`liberator-api` пока не умеет выдавать сессии для VLESS/Hysteria2 (в
`node_protocols` нет `vless`, а `/v1/connect` требует `client_public_key`).
Поэтому proxy-пользователи задаются статически в `router.transports.<name>.users`.
Их `virtual_ip` должен быть вне диапазона, который API выдаёт автоматически.
Когда API научится отдавать proxy-сессии, нода уже умеет маршрутизировать их по
полю `protocol` из `/state.sessions` в нужный транспорт.

Ограничение протоколов: VLESS/Hysteria2 — это proxy, а не IP-туннель. Proxy-клиент
может инициировать трафик (в интернет, к AWG-клиентам и т. п.), но **входящие
соединения к его `virtual_ip`** (client→client из AWG) доставить нельзя: у Xray
нет канала «отправить произвольный IP-пакет клиенту». Для таких сценариев нужен
IP-туннельный протокол (AWG/WireGuard) или отдельный механизм reverse-tunnel.

## Node ↔ API контракт
Полное описание эндпоинтов и потока данных — в `README.md` проекта
`liberator-api` (раздел «Нода»).

Кратко:
- Аутентификация: заголовки `X-Node-Id: <node_id>` + `Authorization: Bearer <per-node secret>`.
  Секрет выдаётся API при enroll и хранится в `api.state_dir/node-identity.json`.
  Первичный enroll — по одноразовому `api.enrollment_token`
- `api.base_url` — адрес API; `api.public_endpoint` — куда клиентам подключаться к
  awg-listen ноды; `api.mesh_endpoint` — QUIC listen этой ноды (host:port), по нему
  остальные ноды форвардят ей пакеты client→client; `api.region_code` — регион.

## Запуск

Первый старт с API требует одноразовый enrollment-token:

```sh
# создать токен в API
curl -H "X-Admin-Key: $LIBERATOR_ADMIN_KEY" -H 'Content-Type: application/json' \
  -d '{"ttl":"1h"}' http://liberator-api:8080/v1/admin/cluster/enrollment-tokens
```

Токен положить в `api.enrollment_token` или `LIBERATOR_NODE_ENROLLMENT_TOKEN`.
После enroll нода сохранит `node_id` + per-node secret в
`api.state_dir/node-identity.json` и будет использовать только их.

```sh
# sysctl на хосте
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
sudo sysctl -w net.ipv4.conf.liberator.rp_filter=0

# конфиг -> args
./liberator-node ./config.yaml
```
