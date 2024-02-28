# Copyright (C) 2015, Fortishield Inc.
# Fortishield repository installation
class fortishield::certificates (
  $fortishield_repository = 'packages.fortishield.github.io',
  $fortishield_version = '4.8',
  $indexer_certs = [],
  $manager_certs = [],
  $manager_master_certs = [],
  $manager_worker_certs = [],
  $dashboard_certs = []
) {
  file { 'Configure Fortishield Certificates config.yml':
    owner   => 'root',
    path    => '/tmp/config.yml',
    group   => 'root',
    mode    => '0640',
    content => template('fortishield/fortishield_config_yml.erb'),
  }

  file { '/tmp/fortishield-certs-tool.sh':
    ensure => file,
    source => "https://${fortishield_repository}/${fortishield_version}/fortishield-certs-tool.sh",
    owner  => 'root',
    group  => 'root',
    mode   => '0740',
  }

  exec { 'Create Fortishield Certificates':
    path    => '/usr/bin:/bin',
    command => 'bash /tmp/fortishield-certs-tool.sh --all',
    creates => '/tmp/fortishield-certificates',
    require => [
      File['/tmp/fortishield-certs-tool.sh'],
      File['/tmp/config.yml'],
    ],
  }
  file { 'Copy all certificates into module':
    ensure => 'directory',
    source => '/tmp/fortishield-certificates/',
    recurse => 'remote',
    path => '/etc/puppetlabs/code/environments/production/modules/archive/files/',
    owner => 'root',
    group => 'root',
    mode  => '0755',
  }
}
