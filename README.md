# liberator-node-go

VPN-шлюз (egress/ingress нода) в распределённой сети Liberator. Нода —
**полностью пассивный** компонент: у неё нет inbound control-plane (кроме
`/healthz` и `/metrics`), она сама ходит в контроль-плоскость (`liberator-api`)
и применяет желаемое состояние.

## Что делает нода
- Поднимает overlay: TUN-интерфейс + NAT в интернет, AmneziaWG-приём клиентов.
- Держит **QUIC-пул** к остальным нодам (общий `auth.secret_key`, список соседей
  из `mesh.dns_service`/`mesh.static`).
- По контракту `/v1/ctrl` с API:
  - саморегистрируется (`/v1/ctrl/nodes/register`, upsert по hostname) и получает `node_id`+`gateway_addr`;
  - шлёт `heartbeat`;
  - тянет желаемое состояние (`/state`) и **реконсилит** локальных клиентов
    (создание/обновление/удаление awg-пиров по `peer_ip`+`client_public_key`,
    лимиты из квот);
  - применяет **firewall-pairs** (`/state.firewall_pairs`) — разрешённые
    client→client потоки по IP-парам (enforcement на источнике);
  - тянет глобальную директорию клиентов (`/ctrl/clients`) и ставит **remote-маршруты**:
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

## Node ↔ API контракт
Полное описание эндпоинтов и потока данных — в `README.md` проекта
`liberator-api` (раздел «Нода ↔ API — `/v1/ctrl/*`»).

Кратко:
- Аутентификация: заголовки `X-Node-Id: <node_id>` + `Authorization: Bearer <secret>`
  (общий `secret_key`, совпадает с `LIBERATOR_NODE_SHARED_SECRET` у API).
- `api.base_url` — адрес API; `api.public_endpoint` — куда клиентам подключаться к
  awg-listen ноды; `api.mesh_endpoint` — QUIC listen этой ноды (host:port), по нему
  остальные ноды форвардят ей пакеты client→client; `api.region_code` — регион.

## Запуск
```sh
# sysctl на хосте
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
sudo sysctl -w net.ipv4.conf.liberator.rp_filter=0

# конфиг -> args
./liberator-node ./config.yaml
```
