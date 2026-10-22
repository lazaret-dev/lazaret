"""Byte mutations for the fuzzers (0.1.9, X-1). Standard library only; the same seed gives the same bytes.

`Mutator(rng, max_len, dictionary).mutate(data, corpus)` applies one to six stacked changes to a copy of
`data`: a flipped bit, a byte set to a value that often matters, inserted or deleted bytes, a span copied or
repeated (for growth), a number rewritten to a boundary value (as text where the input has digits, else as a
binary field), a token of the target's dictionary, a run of opening tokens (nesting), a truncation, and a splice
of another corpus input. The result is never longer than `max_len`."""

import random

# Values that sit on the edges of lengths, counts and sizes.
INTERESTING = (0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 127, 128, 129, 255, 256, 257, 511, 512,
               1000, 1023, 1024, 4095, 4096, 65535, 65536, 2 ** 31 - 1, 2 ** 31, 2 ** 32 - 1, 2 ** 32,
               2 ** 63 - 1, 2 ** 63, 2 ** 64 - 1, 2 ** 64)
BYTES = (0x00, 0x01, 0x09, 0x0A, 0x0D, 0x20, 0x22, 0x27, 0x2E, 0x2F, 0x5C, 0x7F, 0x80, 0xBF, 0xC0, 0xFE, 0xFF)
OPENERS = (b"[", b"{", b"(", b"<a>", b"<!--", b'"', b"'", b"\n  ", b"- ", b"\\")
MAX_STACK = 6
MAX_REPEAT = 256


class Mutator:
    def __init__(self, rng, max_len=65536, dictionary=()):
        self.rng = rng
        self.max_len = max_len
        self.dictionary = tuple(dictionary)
        self.ops = (self.flip_bit, self.set_byte, self.insert_bytes, self.delete_span, self.duplicate_span,
                    self.repeat_span, self.rewrite_number, self.write_int, self.insert_token, self.nest,
                    self.truncate, self.splice, self.swap_spans)

    # -- one change each; every one works on a bytearray in place and copes with an empty one
    def position(self, buf, extra=0):
        return self.rng.randrange(len(buf) + extra) if len(buf) + extra else 0

    def flip_bit(self, buf, corpus):
        if buf:
            buf[self.position(buf)] ^= 1 << self.rng.randrange(8)

    def set_byte(self, buf, corpus):
        if buf:
            buf[self.position(buf)] = self.rng.choice(BYTES)

    def insert_bytes(self, buf, corpus):
        at = self.position(buf, 1)
        buf[at:at] = bytes(self.rng.randrange(256) for _ in range(self.rng.randint(1, 16)))

    def delete_span(self, buf, corpus):
        if buf:
            at = self.position(buf)
            del buf[at:at + self.rng.randint(1, max(1, min(len(buf) - at, 64)))]

    def span(self, buf):
        at = self.position(buf)
        return at, min(len(buf), at + self.rng.randint(1, 32))

    def duplicate_span(self, buf, corpus):
        if buf:
            start, end = self.span(buf)
            buf[end:end] = buf[start:end]

    def repeat_span(self, buf, corpus):
        if buf:
            start, end = self.span(buf)
            piece = bytes(buf[start:end])
            room = max(0, self.max_len - len(buf))
            count = self.rng.choice((2, 4, 16, 64, MAX_REPEAT))
            buf[end:end] = (piece * count)[:room]

    def rewrite_number(self, buf, corpus):
        """A run of ASCII digits becomes a boundary value; without one, a binary field is written instead."""
        starts = [i for i in range(len(buf)) if 0x30 <= buf[i] <= 0x39 and (i == 0 or not 0x30 <= buf[i - 1] <= 0x39)]
        if not starts:
            return self.write_int(buf, corpus)
        at = self.rng.choice(starts)
        end = at
        while end < len(buf) and 0x30 <= buf[end] <= 0x39:
            end += 1
        value = self.rng.choice(INTERESTING)
        buf[at:end] = str(self.rng.choice((value, -value, value + 1, max(0, value - 1)))).encode("ascii")

    def write_int(self, buf, corpus):
        if not buf:
            return
        width = self.rng.choice((1, 2, 4, 8))
        value = self.rng.choice(INTERESTING) & ((1 << (8 * width)) - 1)
        at = self.position(buf)
        data = value.to_bytes(width, self.rng.choice(("little", "big")))
        buf[at:at + width] = data

    def insert_token(self, buf, corpus):
        if self.dictionary:
            at = self.position(buf, 1)
            buf[at:at] = self.rng.choice(self.dictionary)

    def nest(self, buf, corpus):
        at = self.position(buf, 1)
        opener = self.rng.choice(OPENERS + self.dictionary[:8])
        buf[at:at] = (opener * self.rng.choice((8, 64, 512, 4096)))[:max(0, self.max_len - len(buf))]

    def truncate(self, buf, corpus):
        if buf:
            del buf[self.position(buf):]

    def splice(self, buf, corpus):
        if corpus:
            other = self.rng.choice(corpus)
            if other:
                start = self.rng.randrange(len(other))
                piece = other[start:start + self.rng.randint(1, 512)]
                at = self.position(buf, 1)
                buf[at:at + self.rng.randint(0, len(piece))] = piece

    def swap_spans(self, buf, corpus):
        if len(buf) > 4:
            a, b = sorted((self.position(buf), self.position(buf)))
            width = min(b - a, len(buf) - b, self.rng.randint(1, 16))
            if width > 0:
                buf[a:a + width], buf[b:b + width] = buf[b:b + width], buf[a:a + width]

    def mutate(self, data, corpus=()):
        buf = bytearray(data)
        for _ in range(self.rng.choice((1, 1, 1, 2, 2, 3, 4, MAX_STACK))):
            self.rng.choice(self.ops)(buf, corpus)
        del buf[self.max_len:]
        return bytes(buf)


def rng_for(seed, name):
    """The generator of one target for one seed (a str seed is hashed the same way on every run and version)."""
    return random.Random(f"{seed}:{name}")
