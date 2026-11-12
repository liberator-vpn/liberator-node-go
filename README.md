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
  - enroll/перерегистрация по enrollment-токену (`/v1/node/enroll`) и получает `node_id`, per-node secret, `gateway_addr`;
  - шлёт `heartbeat`;
  - тянет желаемое состояние (`/state`) и **реконсилит** локальных клиентов
    (создание/обновление/удаление AWG-пиров по `peer_ip`+`client_public_key`,
    лимиты из квот);
  - применяет **firewall-pairs** (`/state.firewall_pairs`) — разрешённые
    client→client потоки по IP-парам (enforcement на источнике). API компилирует
    их из `VirtualNetwork`: полный mesh внутри сети и изоляция между сетями;
  - тянет глобальную директорию клиентов (`/v1/node/clients`) и ставит **remote-маршруты**:
    клиент другой ноды → пересылка датаграмм через QUIC-пул на её `mesh_endpoint`
    (client→client);
  - применяет **policy** из `/state.policies` (`{peer_ip, prefix, action, exit_mesh_endpoint, tier, ...}`):
    `exit` форвардит трафик на ноду-выход (она NATит), `direct` отправляет в локальный NAT,
    `deny` дропает пакеты. Приоритет: user-правила (`tier=0`) всегда выше групповых (`tier=1`),
    внутри уровня — specificity → group priority → rule priority → стабильный ID;
  - `blocked_prefixes` (`{peer_ip, prefix}`) дублирует `deny`-правила для обратной совместимости;
  - подтверждает активацию сессий (`sessions/activate`, `issued → active`);
  - пушит дельты трафика по сессиям (`/v1/node/usage`); это телеметрия, не billing.
- Отдаёт метрики Prometheus (`node_traffic_bytes_total`, `node_packet_lifetime_seconds`,
  счётчики клиентов/пула) на `/metrics`.

Нода ничего не аллоцирует и не хранит в БД: `peer_ip` клиентам и `gateway_addr`
ноде выдаёт API из общего overlay-пула.

### Proxy-протоколы и control-plane

`liberator-api` теперь принимает произвольные протоколы в `node_protocols`
(жёсткого CHECK на `awg` больше нет). Нода сама анонсирует `amnesiav2`,
`amnesiav31`, `vless`, `hysteria2` из своего конфига при `POST /v1/node/enroll`.

Динамические proxy-сессии работают так же, как AWG: API отдаёт сессию в
`/v1/node/state`, нода направляет её в Xray-транспорт по `protocol`.
`client_auth` из `/v1/connect` для VLESS — UUID, для Hysteria2 — пароль.

Статические пользователи (`router.transports.xray.users`) остаются удобным
способом завести proxy-доступ без клиентского приложения. Их `virtual_ip` должен
быть вне диапазона, который API выдаёт автоматически.

Docker-образ ноды уже содержит `xray-core` (`/usr/local/bin/xray`), а
`docker-compose.yml` монтирует `./state` в `/var/lib/liberator` для identity.

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
  Enroll/перерегистрация — по `api.enrollment_token` (одноразовому или общему reusable).
- `api.base_url` — адрес API; `api.public_endpoint` — куда клиентам подключаться к
  amnesiav2/amnesiav31-listen ноды; `api.mesh_endpoint` — QUIC listen этой ноды (host:port), по нему
  остальные ноды форвардят ей пакеты client→client; `api.region_code` — регион.

## Как добавить ноду в сеть

1. В API создать общий вечный enrollment-token (reusable, без срока):

   ```bash
   curl -sS \
     -H "X-Admin-Key: $LIBERATOR_ADMIN_KEY" \
     -H 'Content-Type: application/json' \
     -d '{"reusable":true,"ttl":""}' \
     http://liberator-api:8080/v1/admin/cluster/enrollment-tokens
   ```

   Для одной ноды можно выпустить персональный токен: `{"reusable":true,"ttl":"","name":"edge-1"}`.
   Одноразовый токен тоже поддерживается: `{"ttl":"1h"}`.

2. В `config.yaml` ноды указать:

   ```yaml
   api:
     base_url: "http://liberator-api:8080"
     region_code: "de"
     public_endpoint: "<IP_НОДЫ>:2200"
     mesh_endpoint: "<IP_НОДЫ>:9000"
     enrollment_token: "<token>"
     node_name: "edge-1"          # стабильное имя ноды
     state_dir: "/var/lib/liberator"
     agent_version: "1.0.0"
   ```

3. Открыть на хосте:
   - `2200/udp` — клиентам amnesiav2;
   - `2201/udp` — клиентам amnesiav31;
   - `9000/udp` — другим нодам;
   - `8080/tcp` — только внутри кластера.

4. Запустить:

   ```bash
   ./liberator-node ./config.yaml
   ```

5. Нода сама вызовет `POST /v1/node/enroll`, получит `node_id`, per-node secret и
   `gateway_addr`, сохранит их в `state_dir/node-identity.json` и начнёт слать
   heartbeat. В админке нода появится в `/v1/admin/cluster/nodes`, а `live`
   станет `true` после первого heartbeat.

`state_dir` может быть и не persistent: при потере identity нода снова вызовет
`POST /v1/node/enroll` по reusable-токену, API найдёт её по `node_name`, сохранит
`node_id`/`gateway_addr`/группы/размещение ключей и выдаст новый per-node secret.
Поэтому `node_name` должен быть стабильным (в k8s — `NODE_NAME`/`spec.nodeName`,
в Docker — явный `api.node_name`).

Ротация секрета (`rotate-secret`) выдаёт новый secret; нода читает identity только
при старте, поэтому после ротации нужно обновить `node-identity.json` и
перезапустить ноду.

## Запуск

```sh
# sysctl на хосте
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo sysctl -w net.ipv4.conf.default.rp_filter=0

# конфиг -> args
./liberator-node ./config.yaml
```
