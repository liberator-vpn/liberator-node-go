package router

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func bigDNSAnswer(t *testing.T, records int) []byte {
	t.Helper()
	var msg dns.Msg
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Response = true
	for i := 0; i < records; i++ {
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(10, 0, byte(i>>8), byte(i)),
		})
	}
	out, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Ответ, который после инкапсуляции не влезает в туннель, должен быть
// обрезан с TC=1, иначе AWG-транспорт падает с sendmmsg: message too long.
func TestDNSAnswerFitsTunnelMTU(t *testing.T) {
	r := newPolicyRouter(t)
	const mtu = 1280
	r.SetMTU(mtu)

	answer := bigDNSAnswer(t, 200)
	maxPayload := mtu - 20 - 8
	if len(answer) <= maxPayload {
		t.Fatalf("test answer is too small: %d", len(answer))
	}

	got := r.fitDNSAnswer(answer)
	if len(got) == 0 {
		t.Fatal("answer dropped")
	}
	if len(got) > maxPayload {
		t.Fatalf("answer %d bytes > max payload %d", len(got), maxPayload)
	}

	var msg dns.Msg
	if err := msg.Unpack(got); err != nil {
		t.Fatalf("truncated answer does not parse: %v", err)
	}
	if !msg.Truncated {
		t.Fatal("TC bit is not set on truncated answer")
	}
}

// Маленький ответ не трогаем.
func TestDNSAnswerKeptWhenFits(t *testing.T) {
	r := newPolicyRouter(t)
	r.SetMTU(1280)

	answer := bigDNSAnswer(t, 2)
	got := r.fitDNSAnswer(answer)
	if len(got) != len(answer) {
		t.Fatalf("small answer changed: %d -> %d", len(answer), len(got))
	}
}

// Без MTU ограничения не применяем (обратная совместимость).
func TestDNSAnswerUntouchedWithoutMTU(t *testing.T) {
	r := newPolicyRouter(t)
	r.SetMTU(0)

	answer := bigDNSAnswer(t, 200)
	if got := r.fitDNSAnswer(answer); len(got) != len(answer) {
		t.Fatalf("answer changed with mtu=0: %d -> %d", len(answer), len(got))
	}
}
