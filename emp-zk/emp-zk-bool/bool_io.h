#ifndef __EMP_BITIO_H__
#define __EMP_BITIO_H__
#include "emp-tool/emp-tool.h"

namespace emp {
using namespace std;
// Bit-level IOChannel adapter for emp-zk-bool. Wraps an inner IOChannel and
// buffers single bits (send_bit / recv_bit), flushing them packed 8-per-byte
// through the inner channel's send_bool / recv_bool. The Fiat-Shamir
// transcript lives on the INNER channel (enabled here), so it absorbs every
// byte that actually crosses the wire — packed gate bits, byte sends, Ferret
// OT — in true wire order. Callers read it via `io->get_digest()` on the inner
// channel; there is no separate hash here to keep in sync.
// The constructor takes a third argument since this change: BoolIO(io, sender,
// transcript).  Callers test this macro to pass it.
#define EMP_ZK_BOOLIO_TRANSCRIPT_FLAG 1

class BoolIO : public IOChannel {
public:
  IOChannel *io;
  // Staging buffer of unpacked bools, flushed via the inner channel's
  // send_bool / recv_bool (which pack 8 bools per wire byte). Raw bool[]
  // (not vector<bool>, which is bit-packed) so we hand send_bool a real bool*.
  std::unique_ptr<bool[]> buf;
  int ptr;
  bool sender;
  // transcript: hash every byte of the inner channel for the Fiat-Shamir
  // challenges of emp-zk-bool and of permutation proofs (default, as before).
  // A caller whose challenges are all verifier-sent (emp-zk-arith alone) can
  // pass false and skip the hash, which costs about 9 s per GB on processors
  // without SHA instructions.  The VOLE's own consistency checks enable the
  // transcript on the channel they are given, so they are not affected.
  BoolIO(IOChannel *io, int sender, bool transcript = true) : io(io), sender(sender) {
    // FS transcript on the inner channel; exactly one party passes true and
    // sender (= party == ALICE) satisfies that. Guard so re-wrapping a channel
    // that already has FS on is a no-op rather than an assert / reset.
    if (transcript && !io->fs_enabled())
      io->enable_fs(sender);
    buf.reset(new bool[NETWORK_STAGING_BUFFER_SIZE]);
    if (sender)
      ptr = 0;
    else
      ptr = NETWORK_STAGING_BUFFER_SIZE;
  }
  ~BoolIO() { this->flush(); }
  void flush() override {
    if (sender) {
      if (ptr != 0) {
        bool data = true;
        while (ptr != 0)
          send_bit(data);
      }
    } else {
      ptr = NETWORK_STAGING_BUFFER_SIZE;
    }
    io->flush();
  }

  void send_bit(bool data) {
    buf[ptr] = data;
    ptr++;
    if (ptr == NETWORK_STAGING_BUFFER_SIZE) {
      io->send_bool(buf.get(), NETWORK_STAGING_BUFFER_SIZE);
      ptr = 0;
    }
  }

  bool recv_bit() {
    if (ptr == NETWORK_STAGING_BUFFER_SIZE) {
      io->recv_bool(buf.get(), NETWORK_STAGING_BUFFER_SIZE);
      ptr = 0;
    }
    bool res = buf[ptr];
    ptr++;
    return res;
  }

  // Pending bits must reach the wire before any byte op so the bit and byte
  // streams stay ordered on the shared connection.
  void send_data_internal(const void *data, int64_t nbyte) override {
    if (ptr != 0)
      flush();
    io->send_data(data, nbyte);
  }

  void recv_data_internal(void *data, int64_t nbyte) override {
    if (ptr != NETWORK_STAGING_BUFFER_SIZE)
      flush();
    io->recv_data(data, nbyte);
  }
};
} // namespace emp
#endif // __UNIDIRIO_H__
