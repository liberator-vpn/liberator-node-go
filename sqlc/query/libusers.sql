-- name: ListUsers :many
select * from libusers;
-- name: GetUserById :one
select * from libusers where id = $1 limit 1;

-- name: InsertUserPortRule :exec 
insert into user_ports (user1, target_user, protocol, port_start, port_end) values ($1,$2,$3,$4,$5);

-- name: ListUserPortsRules :many
select * from user_ports where user1 = $1;
