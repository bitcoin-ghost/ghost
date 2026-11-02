#!/bin/sh
#
# Bitcoin Ghost: retired installer URL.
#
# This file used to be a v1.4 installer for the old Ghost network. It is kept
# only so that old instructions pointing at https://get.bitcoinghost.org/install.sh
# fail safely: it installs nothing, changes nothing and exits non-zero.
#
# The node pool installer is scripts/install-node.sh in the repository. It is
# deliberately NOT fetched from here: no node pool release has been published,
# and the installer refuses to run without GHOST_VERSION naming one.

cat >&2 <<'MSG'

  Bitcoin Ghost: this installer has been retired.

  Nothing was installed and nothing on this machine was changed.

  The old network this script installed is being replaced by the node pool.
  The node pool installer is scripts/install-node.sh in
  https://github.com/bitcoin-ghost/ghost

  No node pool release has been published yet. When one is, the install
  command and everything it does are documented at:

      https://bitcoinghost.org/docs/#deployment

  The node pool is NOT READY: it has never found a block and never made a
  payout. Read https://bitcoinghost.org/docs/#honest-reading first.

MSG
exit 1
