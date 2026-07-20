-- name: LoadAllRules :many
SELECT 
    pr.id,
    pr.peer_id,
    p.virtual_ip,
    pr.target_ip,
    pr.protocol,
    pr.port_range_start,
    pr.port_range_end
FROM peers_rules pr
JOIN peers p ON pr.peer_id = p.id;

-- name: InsertPeerRule :one
INSERT INTO peers_rules (
    peer_id, target_ip, protocol, port_range_start, port_range_end
) VALUES (?, ?, ?, ?, ?)
RETURNING id;

-- name: DeletePeerRule :exec
DELETE FROM peers_rules WHERE id = ?;

-- name: DeleteAllPeerRules :exec
DELETE FROM peers_rules WHERE peer_id = ?;

-- name: LoadRulesByPeerID :many
SELECT
    id,
    peer_id,
    target_ip,
    protocol,
    port_range_start,
    port_range_end
FROM peers_rules
WHERE peer_id = sqlc.arg(peer_id)
ORDER BY id;