-- +goose Up
-- +goose StatementBegin
create table libusers
(
    id    uuid default gen_random_uuid() not null
        constraint libusers_pk
            primary key,
    created_at timestamp default now(),

    login text                           not null
        constraint libusers_pk_login
            unique
);

create table user_ports
(
    id              bigint generated always as identity
        constraint account_usage_logs_pk
            primary key,
    created_at timestamp default now(),

    user1 uuid constraint routing_table_libusers_id1_fk references libusers,
    target_user uuid constraint routing_table_libusers_id2_fk references libusers, -- если NULL то открыт для всех

    protocol VARCHAR(10) NOT NULL CHECK (protocol IN ('tcp', 'udp', 'both')),
    port_start INT NOT NULL CHECK (port_start >= 1 AND port_start <= 65535),
    port_end INT CHECK (port_end >= port_start AND port_end <= 65535), -- если NULL, то только один порт

    CONSTRAINT unique_pair UNIQUE (user1, target_user)
);

CREATE INDEX user_ports_user1_target_user ON user_ports (user1, target_user);
CREATE INDEX user_ports_target_user_user1 ON user_ports (target_user, user1);



-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
drop table if exists libusers;
drop table if exists user_ports;
-- +goose StatementEnd
