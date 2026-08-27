package rarengine

import (
	"errors"
	"math"
	"testing"
)

// int32Modulus is where a 32-bit int wraps. Named because the property below
// is about that exact number and nothing else.
const int32Modulus = int64(1) << 32

// offsetForSlot models decodeOffset's distance accumulation with no width
// limit -- the value the arithmetic MEANS, before any platform truncates it.
//
//	offset := 1
//	bitCount := uint8(slot/2 - 1)
//	offset += (2 | (slot & 1)) << bitCount
//	offset += extra << 4    // extra from ReadBits(bitCount-4)
//	offset += low           // low from the 16-symbol low-offset table
func offsetForSlot(slot int, extra, low int64) int64 {
	if slot < 4 {
		return 1 + int64(slot)
	}
	bitCount := slot/2 - 1
	v := int64(1) + int64(2|(slot&1))<<uint(bitCount)
	if bitCount >= 4 {
		return v + extra<<4 + low
	}
	return v + extra
}

// offsetSlotRange reports the lowest and highest distance a slot can name.
// The terms are independent and each is monotone, so the extremes of the
// inputs give the extremes of the sum.
func offsetSlotRange(slot int) (lo, hi int64) {
	if slot < 4 {
		v := offsetForSlot(slot, 0, 0)
		return v, v
	}
	bitCount := slot/2 - 1
	if bitCount >= 4 {
		var maxExtra int64
		if k := bitCount - 4; k > 0 {
			maxExtra = int64(1)<<uint(k) - 1
		}
		maxLow := int64(lowoffsetSize5) - 1
		return offsetForSlot(slot, 0, 0), offsetForSlot(slot, maxExtra, maxLow)
	}
	maxExtra := int64(1)<<uint(bitCount) - 1
	return offsetForSlot(slot, 0, 0), offsetForSlot(slot, maxExtra, 0)
}

// A crafted offset slot must not name a distance that a 32-bit build accepts
// and a 64-bit build refuses.
//
// slot comes off the compressed stream and reaches 63, so bitCount reaches 30
// and the shift alone reaches 3<<30 -- past what an int32 holds. decodeOffset
// accumulates in an int, so where int is 32 bits that addition wraps, and the
// wrapped value goes to CopyBytes as a distance.
//
// CopyBytes refuses it either way, but by different guards: a value that fits
// is far beyond historyLen(), and a value that wrapped is <= 0. The second one
// is documented as keeping srcIdx in range, not as the 32-bit backstop it also
// is -- weaken it and 64-bit stays correct while 32-bit gains a distance
// pointing outside the window's real history.
//
// The property that makes the wrap safe is narrow: every reachable offset is
// at most 2^32. Values in [2^31, 2^32) truncate NEGATIVE and 2^32 truncates to
// exactly 0, so all of them fail "distance <= 0". One byte further and a
// 32-bit build would compute a small positive distance from a stream a 64-bit
// build rejects -- the same archive read as content on one platform and as an
// error on the other.
//
// A wrapped offset also survives into d.offset[], the four-entry history that
// the repeated-match symbols reuse -- sym 257 and decodeLength both hand
// d.offset[0] straight to CopyBytes. That costs nothing here: those paths copy
// a stored offset verbatim and never do arithmetic on it, so a value that was
// non-positive when computed is still non-positive when replayed, and the same
// guard turns it away. Worth stating because the store happens BEFORE the
// CopyBytes call that rejects it, so the bad value is in the history either
// way; what stops it mattering is that the decode aborts on the error.
//
// Written against explicit int64/int32 models rather than the host's int, for
// the reason the E8 sign tests give: a property about a 32-bit type must not
// be checked by arithmetic that only has that width on the platform running
// the test. CI now also runs the suite under GOARCH=386, which exercises the
// real decodeOffset; this pins the arithmetic independent of either.
func TestOffsetSlotOverflowCannotAliasAValidDistance(t *testing.T) {
	for slot := range offsetSize5 {
		lo, hi := offsetSlotRange(slot)
		if lo > hi {
			t.Fatalf("slot %d: range is inverted (%d..%d); the model no "+
				"longer matches decodeOffset", slot, lo, hi)
		}
		if hi > int32Modulus {
			t.Fatalf("slot %d reaches %d, past 2^32 by %d. Distances above "+
				"2^32 truncate to SMALL POSITIVE ints, so a 32-bit build "+
				"would accept a back-reference a 64-bit build refuses",
				slot, hi, hi-int32Modulus)
		}
		// Everything past int32 must truncate non-positive. Sampled at both
		// ends and the midpoint: truncation is affine over a range this
		// narrow, so an interior violation cannot hide between them.
		if hi <= math.MaxInt32 {
			continue
		}
		for _, v := range []int64{max(lo, math.MaxInt32+1), hi, (max(lo, math.MaxInt32+1) + hi) / 2} {
			if got := int32(v); got > 0 { //nolint:gosec // the truncation IS the subject
				t.Fatalf("slot %d: offset %d truncates to %d, a distance "+
					"CopyBytes accepts on a 32-bit build", slot, v, got)
			}
		}
	}
}

// The margin on the property above is exactly zero, and that is worth knowing.
//
// RAR5's dictionary maxes at 4 GB -- the size field is a 4-bit exponent,
// 128KB<<15 -- so the offset encoding tops out at a distance of exactly 2^32,
// which is exactly where a 32-bit int wraps. The two numbers are the same
// number for a structural reason rather than by luck, but they are EQUAL, not
// merely close: the largest distance the format can express is the one value
// that truncates to 0 rather than to a positive.
//
// Pinned so that a change to offsetSize5, lowoffsetSize5, or the slot formula
// says so here rather than by a 32-bit-only decode divergence found later.
func TestOffsetEncodingTopsOutExactlyAtTheInt32Wrap(t *testing.T) {
	var maxOffset int64
	for slot := range offsetSize5 {
		if _, hi := offsetSlotRange(slot); hi > maxOffset {
			maxOffset = hi
		}
	}
	if maxOffset != int32Modulus {
		t.Fatalf("largest representable distance = %d, want exactly 2^32 (%d).\n"+
			"Below it, this is only a stale test. ABOVE it, the offset "+
			"encoding can now name distances that truncate to small positive "+
			"ints on a 32-bit build -- see "+
			"TestOffsetSlotOverflowCannotAliasAValidDistance",
			maxOffset, int32Modulus)
	}
}

// Both sides of the wrap must actually be refused, not merely be values this
// library believes it would refuse.
//
// The companion to the arithmetic above: that one shows the truncation is
// never a small positive, this one shows CopyBytes turns away what the
// truncation produces on either platform.
func TestCopyBytesRefusesBothSidesOfTheOffsetOverflow(t *testing.T) {
	w := newWindow(1024)
	if err := w.BeginFile(false); err != nil {
		t.Fatalf("BeginFile: %v", err)
	}
	w.recordHistory([]byte("some history to copy from"))

	cases := []struct {
		name     string
		distance int64
	}{
		{"slot 63 wrapped, as on a 32-bit build", -1073741823},
		{"slot 63 at its maximum, which truncates to zero", 0},
		{"slot 63 unwrapped, as on a 64-bit build", 3221225473},
		{"one past the history actually written", int64(w.historyLen()) + 1},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Skipped rather than silently retargeted where int is 32 bits and
			// the value does not fit: the 64-bit shape is not reachable there,
			// and a test that quietly changes what it asserts by platform is
			// worse than one that says it did not run.
			if int64(int(c.distance)) != c.distance {
				t.Skipf("distance %d is not representable in an int on this "+
					"platform, so it is not a shape decodeOffset produces here",
					c.distance)
			}
			err := w.CopyBytes(4, int(c.distance))
			if !errors.Is(err, ErrWindowOffsetBounds) {
				t.Fatalf("CopyBytes(4, %d) = %v, want ErrWindowOffsetBounds",
					c.distance, err)
			}
		})
	}
}
