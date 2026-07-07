-- name: ListUsers :many
select * from libusers;


-- name: GetUserById :one
select * from libusers where id = $1 limit 1;

-- name: ListUserRules :many
select * from libusers where user = $1;

-- name: InsertPendingInterconnection :exec 
INSERT INTO user_interconnections (user1_id, user2_id, status)
VALUES (LEAST($1::uuid, $2::uuid), GREATEST($1::uuid, $2::uuid), 'pending')
ON CONFLICT (user1_id, user2_id) DO NOTHING;

-- name: IsApprovedInterconnection :one
select 1 from user_interconnections where (user1_id = $1 and user2_id = $2 or user1_id = $2 and user2_id = $1) and status = 'approved' limit 1;


-- name: ListUserApprovedInterconnections :many
SELECT user1_id, user2_id
FROM user_interconnections
WHERE (user1_id = $1 OR user2_id = $1)
  AND status = 'approved'
ORDER BY created_at DESC;