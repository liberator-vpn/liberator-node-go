-- name: CreatePeerAutoID :one
INSERT INTO peers (
    type,
    virtual_ip,
    awg_private_key,
    awg_public_key,
    expiration_date
) VALUES (
    sqlc.arg(type),
    sqlc.arg(virtual_ip),
    sqlc.arg(awg_private_key),
    sqlc.arg(awg_public_key),
    sqlc.arg(expiration_date)
)
RETURNING *;


-- name: CreatePeerExplicit :one
INSERT INTO peers (
    id,
    type,
    virtual_ip,
    awg_private_key,
    awg_public_key,
    expiration_date
) VALUES (
    sqlc.arg(id),
    sqlc.arg(type),
    sqlc.arg(virtual_ip),
    sqlc.arg(awg_private_key),
    sqlc.arg(awg_public_key),
    sqlc.arg(expiration_date)
)
RETURNING *;

-- name: GetPeerByID :one
SELECT * FROM peers
WHERE id = sqlc.arg(id);

-- name: GetPeerByVirtualIP :one
SELECT * FROM peers
WHERE virtual_ip = sqlc.arg(virtual_ip);

-- name: ListPeers :many
SELECT * FROM peers
ORDER BY id;

-- name: UpdatePeerLastSeen :exec
UPDATE peers
SET
    last_seen = sqlc.arg(last_seen),
    expiration_date = sqlc.arg(expiration_date)
WHERE id = sqlc.arg(id);

-- name: IncrementPeerCounters :exec
UPDATE peers
SET
    from_peer_total = from_peer_total + sqlc.arg(from_inc),
    to_peer_total   = to_peer_total + sqlc.arg(to_inc)
WHERE id = sqlc.arg(id);

-- name: DeletePeer :exec
DELETE FROM peers
WHERE id = sqlc.arg(id);

