-- name: GetUserById :one
select * from libusers where id = $1 limit 1;


-- name: ListUserRules :many
select * from libusers where user = $1;
