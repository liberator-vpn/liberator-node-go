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

create table user_interconnections
(
    id              bigint generated always as identity
        constraint account_usage_logs_pk
            primary key,
    created_at timestamp default now(),

    user1_id uuid constraint routing_table_libusers_id1_fk references libusers, 
    user2_id uuid constraint routing_table_libusers_id2_fk references libusers, 

    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),

    CONSTRAINT unique_pair UNIQUE (user1_id, user2_id)
);

CREATE INDEX user_interconnections_user1_user2 ON user_interconnections (user1_id, user2_id);
CREATE INDEX user_interconnections_user2_user1 ON user_interconnections (user2_id, user1_id);




-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
drop table if exists libusers;
drop table if exists user_interconnections;
-- +goose StatementEnd
