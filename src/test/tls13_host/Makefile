BSSL := ../../../external/bearssl
CFLAGS := -I../../../include -I../.. -I../../net-synth -I$(BSSL)/inc -I$(BSSL)/src -O2 -Wall
LIB := $(BSSL)/build/libbearssl.a
SRC := ../../net-synth/tls13_wire.c ../../net-synth/tls13_keysched.c
SRC_AEAD := $(SRC) ../../net-synth/tls13_aead.c
# tls13.c now contains the inbound_feed driver → it needs the AEAD + RNG units.
SRC_DRV   := $(SRC) ../../net-synth/tls13.c ../../net-synth/tls13_sign.c \
             ../../net-synth/tls13_aead.c ../../net-synth/tls_rng.c
SRC_PARSE := $(SRC_DRV)
SRC_SER   := $(SRC_DRV)
SRC_HRR   := $(SRC_DRV)
SRC_ECDHE := $(SRC_DRV)
# Self-checking tests: each exits non-zero (assert/abort) on failure.  test_sign
# is the one exception (it emits bytes verified out-of-band by verify_sign.py).
TESTS := test_wire test_keysched test_schedule test_aead test_parse \
         test_serialize test_driver test_hrr test_ecdhe test_suite \
         test_fingerprint
all: $(TESTS) test_sign
	@echo "== oracle_aead self-check (NIST CAVP GCM-256 KAT) =="; python3 oracle_aead.py --selfcheck
	@for t in $(TESTS); do echo "== $$t =="; ./$$t || exit 1; done
	@echo "== test_sign =="; ./test_sign | python3 verify_sign.py
test_wire: test_wire.c $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LIB)
test_keysched: test_keysched.c $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LIB)
test_schedule: test_schedule.c $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LIB)
# oracle_aead.py is the golden source (Python AESGCM + NIST CAVP GCM-256 KAT);
# it is order-only so it does not feed the C compiler line via $^.
test_aead: test_aead.c $(SRC_AEAD) | oracle_aead.py
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.a,$^) $(LIB)
test_sign: test_sign.c ../../net-synth/tls13_sign.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIB)
test_parse: test_parse.c $(SRC_PARSE)
	$(CC) $(CFLAGS) -o $@ $^ $(LIB)
test_serialize: test_serialize.c $(SRC_SER)
	$(CC) $(CFLAGS) -o $@ $^ $(LIB)
test_driver: test_driver.c $(SRC_DRV)
	$(CC) $(CFLAGS) -o $@ $^ $(LIB)
test_hrr: test_hrr.c $(SRC_HRR)
	$(CC) $(CFLAGS) -o $@ $^ $(LIB)
test_ecdhe: test_ecdhe.c $(SRC_ECDHE)
	$(CC) $(CFLAGS) -o $@ $^ $(LIB)
test_suite: test_suite.c $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LIB)
# ε4: pins the ServerHello/HRR extension byte layout (needs the serializers).
test_fingerprint: test_fingerprint.c $(SRC_SER)
	$(CC) $(CFLAGS) -o $@ $^ $(LIB)
clean:
	rm -f $(TESTS) test_sign *.o
