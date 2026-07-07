-- +goose Up
-- +goose StatementBegin
create table libusers
(
    id    uuid default gen_random_uuid() not null
        constraint libusers_pk
            primary key,
    login text                           not null
        constraint libusers_pk_login
            unique
);

create table user_rules_table
(
    id              bigint generated always as identity
        constraint account_usage_logs_pk
            primary key,
    "user" uuid
        constraint routing_table_libusers_id_fk
            references libusers, 
    type   varchar(16) not null,
    value  text        not null
);




-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
drop table if exists libusers;
drop table if exists user_rules_table;
-- +goose StatementEnd
