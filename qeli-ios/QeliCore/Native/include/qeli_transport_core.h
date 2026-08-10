#ifndef QELI_IOS_TRANSPORT_CORE_FORWARD_H
#define QELI_IOS_TRANSPORT_CORE_FORWARD_H

/*
 * The native build replaces this source-tree forwarder with the canonical public header
 * before packaging Qeli.xcframework. Keeping one authoritative ABI declaration prevents the
 * iOS module and the Rust exports from drifting between releases.
 */
#include "../../../../qeli/include/qeli_transport_core.h"

#endif
