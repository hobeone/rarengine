package rarengine

import (
	"testing"
)

func TestHuffmanDecoder_Basic(t *testing.T) {
	// lengths: Symbol 0 = len 2, Symbol 1 = len 2, Symbol 2 = len 1
	lengths := []byte{2, 2, 1}

	var dec HuffmanDecoder
	dec.Init(lengths)

	// Stream contains sequence: [Symbol 2, Symbol 0, Symbol 1, Symbol 2]
	// Bits: 0 (S2), 10 (S0), 11 (S1), 0 (S2) -> 01011000 = 0x58
	buf := []byte{0x58}
	r := NewBitReader(buf, 8)

	// 1. Decode Symbol 2
	s, err := dec.ReadSym(r)
	if err != nil {
		t.Fatalf("ReadSym failed: %v", err)
	}
	if s != 2 {
		t.Errorf("expected symbol 2, got %d", s)
	}

	// 2. Decode Symbol 0
	s, err = dec.ReadSym(r)
	if err != nil {
		t.Fatalf("ReadSym failed: %v", err)
	}
	if s != 0 {
		t.Errorf("expected symbol 0, got %d", s)
	}

	// 3. Decode Symbol 1
	s, err = dec.ReadSym(r)
	if err != nil {
		t.Fatalf("ReadSym failed: %v", err)
	}
	if s != 1 {
		t.Errorf("expected symbol 1, got %d", s)
	}

	// 4. Decode Symbol 2
	s, err = dec.ReadSym(r)
	if err != nil {
		t.Fatalf("ReadSym failed: %v", err)
	}
	if s != 2 {
		t.Errorf("expected symbol 2, got %d", s)
	}
}

func FuzzHuffman(f *testing.F) {
	f.Add([]byte{0x58}, []byte{2, 2, 1})
	f.Fuzz(func(t *testing.T, data []byte, codelen []byte) {
		if len(codelen) > 306 {
			codelen = codelen[:306]
		}
		var dec HuffmanDecoder
		dec.Init(codelen)

		r := NewBitReader(data, len(data)*8)
		for i := 0; i < 100; i++ {
			_, err := dec.ReadSym(r)
			if err != nil {
				break
			}
		}
	})
}
