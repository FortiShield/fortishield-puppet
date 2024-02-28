# Copyright (C) 2015, Fortishield Inc.
# Fortishield repository installation
class fortishield::securityadmin (
  $indexer_init_lockfile = '/var/tmp/indexer-init.lock',
  $indexer_network_host = 'localhost',
) {
  exec { 'Initialize the Opensearch security index and ISM Polciy in Fortishield indexer':
    path    => ['/usr/bin', '/bin', '/usr/sbin', '/sbin'],
    command => "/usr/share/fortishield-indexer/bin/indexer-init.sh -i ${indexer_network_host} && touch ${indexer_init_lockfile}",
    creates => $indexer_init_lockfile,
    require => Service['fortishield-indexer'],
  }
}
