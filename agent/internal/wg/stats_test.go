package wg

import "testing"

func TestParseTransferSumsPeers(t *testing.T) {
	// Two peers, tabs between fields.
	sample := "AAA\t100\t200\nBBB\t50\t75\n"
	got, err := parseTransfer(sample)
	if err != nil {
		t.Fatal(err)
	}
	if got.RXBytes != 150 || got.TXBytes != 275 {
		t.Fatalf("got %+v, want {150 275}", got)
	}
}

func TestParseTransferEmpty(t *testing.T) {
	got, err := parseTransfer("")
	if err != nil {
		t.Fatal(err)
	}
	if got.RXBytes != 0 || got.TXBytes != 0 {
		t.Fatalf("expected zero stats, got %+v", got)
	}
}

func TestParseTransferRejectsBadInt(t *testing.T) {
	if _, err := parseTransfer("AAA\tnotanint\t200\n"); err == nil {
		t.Fatal("expected parse error")
	}
}
