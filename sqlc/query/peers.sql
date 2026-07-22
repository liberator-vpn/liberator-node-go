
-- name: CreatePeerAutoID :one
INSERT INTO peers (
    type,
    virtual_ip,
    expiration_date,
    traffic_limit_gb,
    speed_limit_mbps,
    awg_private_key,
    awg_public_key
) VALUES (
             sqlc.arg(type),
             COALESCE((SELECT MAX(virtual_ip) + 1 FROM peers), 1),
             sqlc.arg(expiration_date),
             sqlc.arg(traffic_limit_gb),
             sqlc.arg(speed_limit_mbps),
             sqlc.arg(awg_private_key),
             sqlc.arg(awg_public_key)
         )
RETURNING *;

-- name: GetPeerByID :one
SELECT * FROM peers WHERE id = sqlc.arg(id);

-- name: GetPeerByVirtualIP :one
SELECT * FROM peers WHERE virtual_ip = sqlc.arg(virtual_ip);

-- name: ListPeers :many
SELECT * FROM peers ORDER BY id;

-- name: DeletePeer :exec
DELETE FROM peers WHERE id = sqlc.arg(id);


-- name: UpdatePeerStats :exec
UPDATE peers
SET
    from_peer_total = from_peer_total + sqlc.arg(from_inc),
    to_peer_total   = to_peer_total + sqlc.arg(to_inc),
    last_seen       = MAX(last_seen, sqlc.arg(last_seen))
WHERE virtual_ip = sqlc.arg(virtual_ip);
