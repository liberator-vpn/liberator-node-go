-- +goose Up
-- +goose StatementBegin

-- Таблица peers (информация о клиентах)
CREATE TABLE peers (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    type             TEXT NOT NULL,                      -- название транспорта, например awg или wg
    virtual_ip       INTEGER NOT NULL UNIQUE,            -- IP-адрес внутри VPN (uint32)
    last_seen        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expiration_date  TIMESTAMP NULL,                     -- NULL = бессрочно
    from_peer_total  INTEGER NOT NULL DEFAULT 0,         -- счётчики (опционально)
    to_peer_total    INTEGER NOT NULL DEFAULT 0,
    awg_private_key  TEXT NOT NULL,
    awg_public_key   TEXT NOT NULL
);

-- Индекс для быстрого поиска по virtual_ip (UNIQUE уже создаёт индекс, но явно укажем)
CREATE UNIQUE INDEX idx_peers_virtual_ip ON peers(virtual_ip);

-- Таблица правил (привязаны к конкретному пиру)
CREATE TABLE peers_rules (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id           INTEGER NOT NULL,
    target_ip         INTEGER NULL,                  -- IP назначения (uint32)
    protocol          TEXT NOT NULL CHECK (protocol IN ('tcp','udp','both')),
    port_range_start  INTEGER NOT NULL,                  -- uint16
    port_range_end    INTEGER NULL,                      -- NULL = только один порт
    FOREIGN KEY (peer_id) REFERENCES peers(id) ON DELETE CASCADE
);

-- Уникальность набора полей, чтобы избежать дублирования правил
CREATE UNIQUE INDEX idx_peers_rules_unique ON peers_rules(peer_id, target_ip, protocol, port_range_start, port_range_end);

-- Индекс для связи по peer_id (ускоряет JOIN)
CREATE INDEX idx_peers_rules_peer_id ON peers_rules(peer_id);


-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
drop table if exists peers;
drop table if exists peers_rules;
-- +goose StatementEnd
