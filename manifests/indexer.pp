# Copyright (C) 2015, Fortishield Inc.
# Setup for Fortishield Indexer
class fortishield::indexer (
  # opensearch.yml configuration
  $indexer_network_host = '0.0.0.0',
  $indexer_cluster_name = 'fortishield-cluster',
  $indexer_node_name = 'node-1',
  $indexer_node_max_local_storage_nodes = '1',
  $indexer_service = 'fortishield-indexer',
  $indexer_package = 'fortishield-indexer',
  $indexer_version = '5.0.0-1',
  $indexer_fileuser = 'fortishield-indexer',
  $indexer_filegroup = 'fortishield-indexer',

  $indexer_path_data = '/var/lib/fortishield-indexer',
  $indexer_path_logs = '/var/log/fortishield-indexer',
  $indexer_path_certs = '/etc/fortishield-indexer/certs',
  $indexer_init_lockfile = '/var/tmp/indexer-init.lock',
  $full_indexer_reinstall = false, # Change to true when whant a full reinstall of Fortishield indexer

  $indexer_ip = 'localhost',
  $indexer_port = '9200',
  $indexer_discovery_hosts = [], # Empty array for single-node configuration
  $indexer_cluster_initial_master_nodes = ['node-1'],
  $indexer_cluster_CN = ['node-1'],

  # JVM options
  $jvm_options_memory = '1g',
) {

  # install package
  package { 'fortishield-indexer':
    ensure => $indexer_version,
    name   => $indexer_package,
  }

  exec { "ensure full path of ${indexer_path_certs}":
    path    => '/usr/bin:/bin',
    command => "mkdir -p ${indexer_path_certs}",
    creates => $indexer_path_certs,
    require => Package['fortishield-indexer'],
  }
  -> file { $indexer_path_certs:
    ensure => directory,
    owner  => $indexer_fileuser,
    group  => $indexer_filegroup,
    mode   => '0500',
  }

  [
   "indexer-$indexer_node_name.pem",
   "indexer-$indexer_node_name-key.pem",
   'root-ca.pem',
   'admin.pem',
   'admin-key.pem',
  ].each |String $certfile| {
    file { "${indexer_path_certs}/${certfile}":
      ensure  => file,
      owner   => $indexer_fileuser,
      group   => $indexer_filegroup,
      mode    => '0400',
      replace => true,
      recurse => remote,
      source  => "puppet:///modules/archive/${certfile}",
    }
  }



  file { 'configuration file':
    path    => '/etc/fortishield-indexer/opensearch.yml',
    content => template('fortishield/fortishield_indexer_yml.erb'),
    group   => $indexer_filegroup,
    mode    => '0660',
    owner   => $indexer_fileuser,
    require => Package['fortishield-indexer'],
    notify  => Service['fortishield-indexer'],
  }

  file_line { 'Insert line initial size of total heap space':
    path    => '/etc/fortishield-indexer/jvm.options',
    line    => "-Xms${jvm_options_memory}",
    match   => '^-Xms',
    require => Package['fortishield-indexer'],
    notify  => Service['fortishield-indexer'],
  }

  file_line { 'Insert line maximum size of total heap space':
    path    => '/etc/fortishield-indexer/jvm.options',
    line    => "-Xmx${jvm_options_memory}",
    match   => '^-Xmx',
    require => Package['fortishield-indexer'],
    notify  => Service['fortishield-indexer'],
  }

  service { 'fortishield-indexer':
    ensure  => running,
    enable  => true,
    name    => $indexer_service,
    require => Package['fortishield-indexer'],
  }

  file_line { "Insert line limits nofile for ${indexer_fileuser}":
    path   => '/etc/security/limits.conf',
    line   => "${indexer_fileuser} - nofile  65535",
    match  => "^${indexer_fileuser} - nofile\s",
    notify => Service['fortishield-indexer'],
  }
  file_line { "Insert line limits memlock for ${indexer_fileuser}":
    path   => '/etc/security/limits.conf',
    line   => "${indexer_fileuser} - memlock unlimited",
    match  => "^${indexer_fileuser} - memlock\s",
    notify => Service['fortishield-indexer'],
  }

  # TODO: this should be done by the package itself and not by puppet at all
  [
    '/etc/fortishield-indexer',
    '/usr/share/fortishield-indexer',
    '/var/lib/fortishield-indexer',
  ].each |String $file| {
    exec { "set recusive ownership of ${file}":
      path        => '/usr/bin:/bin',
      command     => "chown ${indexer_fileuser}:${indexer_filegroup} -R ${file}",
      refreshonly => true,  # only run when package is installed or updated
      subscribe   => Package['fortishield-indexer'],
      notify      => Service['fortishield-indexer'],
    }
  }

  if $full_indexer_reinstall {
    file { $indexer_init_lockfile:
      ensure  => absent,
      require => Package['fortishield-indexer'],
      before  => Exec['Initialize the Opensearch security index in Fortishield indexer'],
    }
  }
}
