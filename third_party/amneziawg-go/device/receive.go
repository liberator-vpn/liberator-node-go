/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type QueueHandshakeElement struct {
	msgType  uint32
	packet   []byte
	endpoint conn.Endpoint
	buffer   *[MaxMessageSize]byte
}

type QueueInboundElement struct {
	buffer   *[MaxMessageSize]byte
	packet   []byte
	counter  uint64
	keypair  *Keypair
	endpoint conn.Endpoint
	padding  uint32
}

type QueueInboundElementsContainer struct {
	sync.Mutex
	elems []*QueueInboundElement
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueInboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.keypair = nil
	elem.endpoint = nil
}

/* Called when a new authenticated message has been received
 *
 * NOTE: Not thread safe, but called by sequential receiver!
 */
func (peer *Peer) keepKeyFreshReceiving() {
	if peer.timers.sentLastMinuteHandshake.Load() {
		return
	}
	keypair := peer.keypairs.Current()

	if keypair != nil && keypair.isInitiator && time.Since(keypair.created) > peer.device.keyRefreshTimeoutReceiving() {
		peer.timers.sentLastMinuteHandshake.Store(true)
		peer.SendHandshakeInitiation(false)
	}
}

/* Receives incoming datagrams for the device
 *
 * Every time the bind is updated a new routine is started for
 * IPv4 and IPv6 (separately)
 */
func (device *Device) RoutineReceiveIncoming(
	maxBatchSize int,
	recv conn.ReceiveFunc,
) {
	recvName := recv.PrettyName()
	defer func() {
		device.log.Verbosef("Routine: receive incoming %s - stopped", recvName)
		device.queue.decryption.wg.Done()
		device.queue.handshake.wg.Done()
		device.net.stopping.Done()
	}()

	device.log.Verbosef("Routine: receive incoming %s - started", recvName)

	// receive datagrams until conn is closed

	var (
		bufsArrs    = make([]*[MaxMessageSize]byte, maxBatchSize)
		bufs        = make([][]byte, maxBatchSize)
		err         error
		sizes       = make([]int, maxBatchSize)
		count       int
		endpoints   = make([]conn.Endpoint, maxBatchSize)
		deathSpiral int
		elemsByPeer = make(map[*Peer]*QueueInboundElementsContainer, maxBatchSize)
		typeHashBuf [4]byte
	)

	for i := range maxBatchSize {
		bufsArrs[i] = device.GetMessageBuffer()
		bufs[i] = bufsArrs[i][:]
	}

	defer func() {
		for i := range maxBatchSize {
			if bufsArrs[i] != nil {
				device.PutMessageBuffer(bufsArrs[i])
			}
		}
	}()

	for {
		count, err = recv(bufs, sizes, endpoints)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			device.log.Verbosef("Failed to receive %s packet: %v", recvName, err)
			if neterr, ok := err.(net.Error); ok && !neterr.Temporary() {
				return
			}
			if deathSpiral < 10 {
				deathSpiral++
				time.Sleep(time.Second / 3)
				continue
			}
			return
		}
		deathSpiral = 0

		// handle each packet in the batch
		for i, size := range sizes[:count] {
			if size < MinMessageSize {
				continue
			}

			// check size of packet
			packet := bufsArrs[i][:size]

			cip, err := device.HeaderProtectionCipher(packet[:HeaderCipherNonceSize])
			if err != nil {
				device.log.Errorf("Failed to initialize header cipher")
				continue
			}

			typeHash := typeHashBuf[:]
			clear(typeHash)
			if cip != nil {
				cip.XORKeyStream(typeHash, typeHash)
			}

			// get message padding and type based on information from S1-S4 and H1-H4
			msgSize, msgType, padding := device.DeterminePacketTypeAndPadding(packet, typeHash)

			packet = packet[padding:]
			if msgType != MessageTransportType {
				packet = packet[:msgSize]
			}

			if cip != nil {
				applyHash(packet[:4], packet[:4], typeHash)
			}

			switch msgType {

			// check if transport

			case MessageTransportType:

				// check size

				if len(packet) < MessageTransportSize {
					continue
				}
				if cip != nil {
					cip.XORKeyStream(packet[4:MessageTransportHeaderSize], packet[4:MessageTransportHeaderSize])
				}

				// lookup key pair

				receiver := binary.LittleEndian.Uint32(
					packet[MessageTransportOffsetReceiver:MessageTransportOffsetCounter],
				)
				value := device.indexTable.Lookup(receiver)
				keypair := value.keypair
				if keypair == nil {
					continue
				}

				// check keypair expiry

				if keypair.created.Add(device.keychainExpireTime()).Before(time.Now()) {
					continue
				}

				// create work element
				peer := value.peer
				elem := device.GetInboundElement()
				elem.packet = packet
				elem.buffer = bufsArrs[i]
				elem.keypair = keypair
				elem.endpoint = endpoints[i]
				elem.counter = 0
				elem.padding = padding

				elemsForPeer, ok := elemsByPeer[peer]
				if !ok {
					elemsForPeer = device.GetInboundElementsContainer()
					elemsForPeer.Lock()
					elemsByPeer[peer] = elemsForPeer
				}
				elemsForPeer.elems = append(elemsForPeer.elems, elem)
				bufsArrs[i] = device.GetMessageBuffer()
				bufs[i] = bufsArrs[i][:]
				continue

			// otherwise it is a fixed size & handshake related packet

			case MessageInitiationType:
				if len(packet) != MessageInitiationSize {
					continue
				}
				if cip != nil {
					cip.XORKeyStream(packet[4:MessageInitiationSize], packet[4:MessageInitiationSize])
				}

			case MessageResponseType:
				if len(packet) != MessageResponseSize {
					continue
				}
				if cip != nil {
					cip.XORKeyStream(packet[4:MessageResponseSize], packet[4:MessageResponseSize])
				}

			case MessageCookieReplyType:
				if len(packet) != MessageCookieReplySize {
					continue
				}
				if cip != nil {
					cip.XORKeyStream(packet[4:MessageCookieReplySize], packet[4:MessageCookieReplySize])
				}

			default:
				device.log.Verbosef("Received message with unknown type")
				continue
			}

			select {
			case device.queue.handshake.c <- QueueHandshakeElement{
				msgType:  msgType,
				buffer:   bufsArrs[i],
				packet:   packet,
				endpoint: endpoints[i],
			}:
				bufsArrs[i] = device.GetMessageBuffer()
				bufs[i] = bufsArrs[i][:]
			default:
			}
		}
		for peer, elemsContainer := range elemsByPeer {
			if peer.isRunning.Load() {
				peer.queue.inbound.c <- elemsContainer
				device.queue.decryption.c <- elemsContainer
			} else {
				for _, elem := range elemsContainer.elems {
					device.PutMessageBuffer(elem.buffer)
					device.PutInboundElement(elem)
				}
				device.PutInboundElementsContainer(elemsContainer)
			}
			delete(elemsByPeer, peer)
		}
	}
}

func (device *Device) RoutineDecryption(id int) {
	var nonce [chacha20poly1305.NonceSize]byte

	defer device.log.Verbosef("Routine: decryption worker %d - stopped", id)
	device.log.Verbosef("Routine: decryption worker %d - started", id)

	for elemsContainer := range device.queue.decryption.c {
		for _, elem := range elemsContainer.elems {
			// split message into fields
			counter := elem.packet[MessageTransportOffsetCounter:MessageTransportOffsetContent]
			content := elem.packet[MessageTransportOffsetContent:]

			// decrypt and release to consumer
			var err error
			elem.counter = binary.LittleEndian.Uint64(counter)
			// copy counter to nonce
			binary.LittleEndian.PutUint64(nonce[0x4:0xc], elem.counter)
			elem.packet, err = elem.keypair.receive.Open(
				content[:0],
				nonce[:],
				content,
				nil,
			)
			if err != nil {
				elem.packet = nil
			}
		}
		elemsContainer.Unlock()
	}
}

/* Handles incoming packets related to handshake
 */
func (device *Device) RoutineHandshake(id int) {
	defer func() {
		device.log.Verbosef("Routine: handshake worker %d - stopped", id)
		device.queue.encryption.wg.Done()
	}()
	device.log.Verbosef("Routine: handshake worker %d - started", id)

	for elem := range device.queue.handshake.c {
		// handle cookie fields and ratelimiting

		switch elem.msgType {

		case MessageCookieReplyType:

			// unmarshal packet

			var reply MessageCookieReply
			reader := bytes.NewReader(elem.packet)
			err := binary.Read(reader, binary.LittleEndian, &reply)
			if err != nil {
				device.log.Verbosef("Failed to decode cookie reply")
				goto skip
			}

			// lookup peer from index

			entry := device.indexTable.Lookup(reply.Receiver)

			if entry.peer == nil {
				goto skip
			}

			// consume reply

			if peer := entry.peer; peer.isRunning.Load() {
				device.log.Verbosef(
					"Receiving cookie response from %s",
					elem.endpoint.DstToString(),
				)
				if !peer.cookieGenerator.ConsumeReply(&reply) {
					device.log.Verbosef(
						"Could not decrypt invalid cookie response",
					)
				}
			}

			goto skip

		case MessageInitiationType, MessageResponseType:

			// check mac fields and maybe ratelimit

			if !device.cookieChecker.CheckMAC1(elem.packet) {
				device.log.Verbosef("Received packet with invalid mac1")
				goto skip
			}

			// endpoints destination address is the source of the datagram

			disableCookies := device.disableCookies.Load()
			if !disableCookies && device.IsUnderLoad() {

				// verify MAC2 field

				if !device.cookieChecker.CheckMAC2(elem.packet, elem.endpoint.DstToBytes()) {
					device.SendHandshakeCookie(&elem)
					goto skip
				}

				// check ratelimiter

				if !device.rate.limiter.Allow(elem.endpoint.DstIP()) {
					goto skip
				}
			}

		default:
			device.log.Errorf("Invalid packet ended up in the handshake queue")
			goto skip
		}

		// handle handshake initiation/response content

		switch elem.msgType {
		case MessageInitiationType:
			// unmarshal
			var msg MessageInitiation
			reader := bytes.NewReader(elem.packet)
			err := binary.Read(reader, binary.LittleEndian, &msg)
			if err != nil {
				device.log.Errorf("Failed to decode initiation message")
				goto skip
			}

			// have to reassign msgType for ranged msgType to work
			msg.Type = elem.msgType

			// consume initiation
			peer := device.ConsumeMessageInitiation(&msg)
			if peer == nil {
				device.log.Verbosef("Received invalid initiation message from %s", elem.endpoint.DstToString())
				goto skip
			}

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// update endpoint
			peer.SetEndpointFromPacket(elem.endpoint)

			device.log.Verbosef("%v - Received handshake initiation", peer)
			peer.rxBytes.Add(uint64(len(elem.packet)))

			peer.SendHandshakeResponse()

		case MessageResponseType:

			// unmarshal

			var msg MessageResponse
			reader := bytes.NewReader(elem.packet)
			err := binary.Read(reader, binary.LittleEndian, &msg)
			if err != nil {
				device.log.Errorf("Failed to decode response message")
				goto skip
			}

			// have to reassign msgType for ranged msgType to work
			msg.Type = elem.msgType

			// consume response

			peer := device.ConsumeMessageResponse(&msg)
			if peer == nil {
				device.log.Verbosef("Received invalid response message from %s", elem.endpoint.DstToString())
				goto skip
			}

			// update endpoint
			peer.SetEndpointFromPacket(elem.endpoint)

			device.log.Verbosef("%v - Received handshake response", peer)
			peer.rxBytes.Add(uint64(len(elem.packet)))

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// derive keypair

			err = peer.BeginSymmetricSession()

			if err != nil {
				device.log.Errorf("%v - Failed to derive keypair: %v", peer, err)
				goto skip
			}

			peer.timersSessionDerived()
			peer.timersHandshakeComplete()
			peer.SendKeepalive()
		}
	skip:
		device.PutMessageBuffer(elem.buffer)
	}
}

// reorderWindow bounds the number of out-of-order inbound elements held per
// peer. At 100 Mbps this is roughly 1.4 MB of inner packets.
const reorderWindow = 1024

// reorderTimeout is how long a gap is tolerated before the receiver skips to
// the lowest buffered counter. WireGuard transport packets are not
// retransmitted; the inner TCP retransmits with a new outer counter, so
// waiting longer only adds latency to every packet behind the gap.
const reorderTimeout = 10 * time.Millisecond

// processInboundElem validates one decrypted element and appends its inner IP
// packet to bufs. It is called in counter order by RoutineSequentialReceiver.
func (peer *Peer) processInboundElem(device *Device, elem *QueueInboundElement, bufs *[][]byte) (valid, data bool, rx uint64) {
	if elem.packet == nil || elem.keypair == nil {
		return false, false, 0
	}
	if !elem.keypair.replayFilter.ValidateCounter(elem.counter, RejectAfterMessages) {
		return false, false, 0
	}
	valid = true
	if peer.ReceivedWithKeypair(elem.keypair) {
		peer.SetEndpointFromPacket(elem.endpoint)
		peer.timersHandshakeComplete()
		peer.SendStagedPackets()
	}
	peer.SetEndpointFromPacket(elem.endpoint)

	rx = uint64(len(elem.packet) + MinMessageSize)
	udpWindow := elem.padding + MessageTransportHeaderSize + uint32(len(elem.packet))
	if peer.udpWindow.Load() < udpWindow {
		peer.udpWindow.Store(udpWindow)
	}

	if len(elem.packet) == 0 || elem.packet[0] == 0 {
		device.log.Verbosef("%v - Receiving keepalive packet", peer)
		return valid, false, rx
	}
	data = true

	switch elem.packet[0] >> 4 {
	case 4:
		if len(elem.packet) < ipv4.HeaderLen {
			return valid, data, rx
		}
		field := elem.packet[IPv4offsetTotalLength : IPv4offsetTotalLength+2]
		length := binary.BigEndian.Uint16(field)
		if int(length) > len(elem.packet) || int(length) < ipv4.HeaderLen {
			return valid, data, rx
		}
		elem.packet = elem.packet[:length]
		src := elem.packet[IPv4offsetSrc : IPv4offsetSrc+net.IPv4len]
		if device.allowedips.Lookup(src) != peer {
			device.log.Verbosef("IPv4 packet with disallowed source address from %v", peer)
			return valid, data, rx
		}

	case 6:
		if len(elem.packet) < ipv6.HeaderLen {
			return valid, data, rx
		}
		field := elem.packet[IPv6offsetPayloadLength : IPv6offsetPayloadLength+2]
		length := binary.BigEndian.Uint16(field)
		length += ipv6.HeaderLen
		if int(length) > len(elem.packet) {
			return valid, data, rx
		}
		elem.packet = elem.packet[:length]
		src := elem.packet[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len]
		if device.allowedips.Lookup(src) != peer {
			device.log.Verbosef("IPv6 packet with disallowed source address from %v", peer)
			return valid, data, rx
		}

	default:
		device.log.Verbosef("Packet with invalid IP version from %v", peer)
		return valid, data, rx
	}

	*bufs = append(*bufs, elem.buffer[int(elem.padding):int(elem.padding)+MessageTransportHeaderSize+len(elem.packet)])
	return valid, data, rx
}

func (peer *Peer) RoutineSequentialReceiver(maxBatchSize int) {
	device := peer.device
	defer func() {
		device.log.Verbosef("%v - Routine: sequential receiver - stopped", peer)
		peer.stopping.Done()
	}()
	device.log.Verbosef("%v - Routine: sequential receiver - started", peer)

	bufs := make([][]byte, 0, maxBatchSize)
	pending := make(map[uint64]*QueueInboundElement)
	released := make([]*QueueInboundElement, 0, maxBatchSize)

	var (
		next        uint64
		haveNext    bool
		keypair     *Keypair
		timer       *time.Timer
		validAny    bool
		dataAny     bool
		releasedAny bool
		rxBytesLen  uint64
	)

	putElem := func(elem *QueueInboundElement) {
		device.PutMessageBuffer(elem.buffer)
		device.PutInboundElement(elem)
	}
	process := func(elem *QueueInboundElement) {
		valid, data, rx := peer.processInboundElem(device, elem, &bufs)
		if valid {
			validAny = true
		}
		if data {
			dataAny = true
		}
		rxBytesLen += rx
		released = append(released, elem)
	}
	flushBuffers := func() {
		if len(bufs) > 0 {
			_, err := device.tun.device.Write(bufs, MessageTransportOffsetContent)
			if err != nil && !device.isClosed() {
				device.log.Errorf("Failed to write packets to TUN device: %v", err)
			}
			bufs = bufs[:0]
		}
		for _, elem := range released {
			putElem(elem)
		}
		released = released[:0]
		if validAny {
			peer.keepKeyFreshReceiving()
			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()
			validAny = false
		}
		if dataAny {
			peer.timersDataReceived()
			dataAny = false
		}
		if rxBytesLen > 0 {
			peer.rxBytes.Add(rxBytesLen)
			rxBytesLen = 0
		}
	}
	lowestPending := func() (uint64, bool) {
		var (
			min   uint64
			found bool
		)
		for counter := range pending {
			if !found || counter < min {
				min = counter
				found = true
			}
		}
		return min, found
	}
	release := func() {
		releasedCount := 0
		for haveNext {
			elem, ok := pending[next]
			if !ok {
				break
			}
			delete(pending, next)
			process(elem)
			releasedCount++
			next++
		}
		if releasedCount > 0 {
			releasedAny = true
		}
		flushBuffers()
	}
	// flushAll is the no-loss fallback: release every buffered element in
	// counter order, even if a gap is missing. The gap is left to inner TCP
	// retransmission; dropping buffered packets would amplify loss.
	flushAll := func() {
		if len(pending) > 0 {
			keys := make([]uint64, 0, len(pending))
			for counter := range pending {
				keys = append(keys, counter)
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			for _, counter := range keys {
				elem := pending[counter]
				delete(pending, counter)
				process(elem)
			}
			releasedAny = true
		}
		haveNext = false
		next = 0
		flushBuffers()
	}

	for {
		var elemsContainer *QueueInboundElementsContainer
		if haveNext && len(pending) > 0 {
			if _, ok := pending[next]; !ok {
				if timer == nil {
					timer = time.NewTimer(reorderTimeout)
				} else {
					timer.Reset(reorderTimeout)
				}
				select {
				case elemsContainer = <-peer.queue.inbound.c:
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
				case <-timer.C:
					flushAll()
					continue
				}
			} else {
				elemsContainer = <-peer.queue.inbound.c
			}
		} else {
			elemsContainer = <-peer.queue.inbound.c
		}

		if elemsContainer == nil {
			flushAll()
			if timer != nil {
				timer.Stop()
			}
			return
		}

		elemsContainer.Lock()
		for _, elem := range elemsContainer.elems {
			if elem.packet == nil || elem.keypair == nil {
				putElem(elem)
				continue
			}
			if elem.keypair != keypair {
				flushAll()
				keypair = elem.keypair
				releasedAny = false
			}
			if !haveNext {
				if _, exists := pending[elem.counter]; exists {
					putElem(elem)
					continue
				}
				pending[elem.counter] = elem
				continue
			}
			if elem.counter < next {
				// Пока не выпустили ни одного пакета текущего keypair,
				// более ранний counter мог прийти во втором контейнере.
				if !releasedAny {
					next = elem.counter
					if _, exists := pending[elem.counter]; exists {
						putElem(elem)
						continue
					}
					pending[elem.counter] = elem
					continue
				}
				// Поздний пакет уже после выпуска: отдаём его сразу,
				// не теряя данные.
				process(elem)
				flushBuffers()
				continue
			}
			if _, exists := pending[elem.counter]; exists {
				putElem(elem)
				continue
			}
			pending[elem.counter] = elem
		}
		if !haveNext {
			if min, ok := lowestPending(); ok {
				next = min
				haveNext = true
			}
		}
		elemsContainer.elems = nil
		elemsContainer.Unlock()
		device.PutInboundElementsContainer(elemsContainer)

		if len(pending) > reorderWindow {
			flushAll()
		}
		release()
	}
}

func applyHash(dst, src, hash []byte) {
	for i := range len(dst) {
		dst[i] = src[i] ^ hash[i]
	}
}

func (device *Device) DeterminePacketTypeAndPadding(packet []byte, typeHash []byte) (int, uint32, uint32) {
	var headerBytes [4]byte
	var padding uint32
	var header UintRange
	var expectedSize int

	size := len(packet)
	randomTrailers := device.randomTrailers.Load()

	padding = device.paddings.init.Load()
	header = device.headers.init.Load()
	expectedSize = int(padding) + MessageInitiationSize

	if size == expectedSize || randomTrailers && size > expectedSize {
		applyHash(headerBytes[:], packet[padding:padding+4], typeHash)
		if header.Contains(binary.LittleEndian.Uint32(headerBytes[:])) {
			return MessageInitiationSize, MessageInitiationType, padding
		}
	}

	padding = device.paddings.response.Load()
	header = device.headers.response.Load()
	expectedSize = int(padding) + MessageResponseSize

	if size == expectedSize || randomTrailers && size > expectedSize {
		applyHash(headerBytes[:], packet[padding:padding+4], typeHash)
		if header.Contains(binary.LittleEndian.Uint32(headerBytes[:])) {
			return MessageResponseSize, MessageResponseType, padding
		}
	}

	padding = device.paddings.cookie.Load()
	header = device.headers.cookie.Load()
	expectedSize = int(padding) + MessageCookieReplySize

	if size == expectedSize || randomTrailers && size > expectedSize {
		applyHash(headerBytes[:], packet[padding:padding+4], typeHash)
		if header.Contains(binary.LittleEndian.Uint32(headerBytes[:])) {
			return MessageCookieReplySize, MessageCookieReplyType, padding
		}
	}

	padding = device.paddings.transport.Load()
	header = device.headers.transport.Load()
	expectedSize = int(padding) + MessageTransportSize

	if size >= expectedSize {
		applyHash(headerBytes[:], packet[padding:padding+4], typeHash)
		if header.Contains(binary.LittleEndian.Uint32(headerBytes[:])) {
			return MessageTransportSize, MessageTransportType, padding
		}
	}

	return 0, MessageUnknownType, 0
}
