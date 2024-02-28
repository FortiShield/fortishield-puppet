# Copyright (C) 2015, Fortishield Inc.
# Setup for Fortishield Dashboard
class fortishield::dashboard (
  $dashboard_package = 'fortishield-dashboard',
  $dashboard_service = 'fortishield-dashboard',
  $dashboard_version = '5.0.0',
  $indexer_server_ip = 'localhost',
  $indexer_server_port = '9200',
  $manager_api_host = '127.0.0.1',
  $dashboard_path_certs = '/etc/fortishield-dashboard/certs',
  $dashboard_fileuser = 'fortishield-dashboard',
  $dashboard_filegroup = 'fortishield-dashboard',

  $dashboard_server_port = '443',
  $dashboard_server_host = '0.0.0.0',
  $dashboard_server_hosts = "https://${indexer_server_ip}:${indexer_server_port}",

  # If the keystore is used, the credentials are not managed by the module (TODO).
  # If use_keystore is false, the keystore is deleted, the dashboard use the credentials in the configuration file.
  $use_keystore = true,
  $dashboard_user = 'kibanaserver',
  $dashboard_password = 'kibanaserver',

  $dashboard_fortishield_api_credentials = [
    {
      'id'       => 'default',
      'url'      => "https://${manager_api_host}",
      'port'     => '55000',
      'user'     => 'fortishield-wui',
      'password' => 'fortishield-wui',
    },
  ],

) {

  # assign version according to the package manager
  case $facts['os']['family'] {
    'Debian': {
      $dashboard_version_install = "${dashboard_version}-*"
    }
    'Linux', 'RedHat', default: {
      $dashboard_version_install = $dashboard_version
    }
  }

  # install package
  package { 'fortishield-dashboard':
    ensure => $dashboard_version_install,
    name   => $dashboard_package,
  }

  exec { "ensure full path of ${dashboard_path_certs}":
    path    => '/usr/bin:/bin',
    command => "mkdir -p ${dashboard_path_certs}",
    creates => $dashboard_path_certs,
    require => Package['fortishield-dashboard'],
  }
  -> file { $dashboard_path_certs:
    ensure => directory,
    owner  => $dashboard_fileuser,
    group  => $dashboard_filegroup,
    mode   => '0500',
  }

  [
    'dashboard.pem',
    'dashboard-key.pem',
    'root-ca.pem',
  ].each |String $certfile| {
    file { "${dashboard_path_certs}/${certfile}":
      ensure  => file,
      owner   => $dashboard_fileuser,
      group   => $dashboard_filegroup,
      mode    => '0400',
      replace => true,
      recurse => remote,
      source  => "puppet:///modules/archive/${certfile}",
    }
  }

  file { '/etc/fortishield-dashboard/opensearch_dashboards.yml':
    content => template('fortishield/fortishield_dashboard_yml.erb'),
    group   => $dashboard_filegroup,
    mode    => '0640',
    owner   => $dashboard_fileuser,
    require => Package['fortishield-dashboard'],
    notify  => Service['fortishield-dashboard'],
  }

  file { [ '/usr/share/fortishield-dashboard/data/fortishield/', '/usr/share/fortishield-dashboard/data/fortishield/config' ]:
    ensure  => 'directory',
    group   => $dashboard_filegroup,
    mode    => '0755',
    owner   => $dashboard_fileuser,
    require => Package['fortishield-dashboard'],
  }
  -> file { '/usr/share/fortishield-dashboard/data/fortishield/config/fortishield.yml':
    content => template('fortishield/fortishield_yml.erb'),
    group   => $dashboard_filegroup,
    mode    => '0600',
    owner   => $dashboard_fileuser,
    notify  => Service['fortishield-dashboard'],
  }

  unless $use_keystore {
    file { '/etc/fortishield-dashboard/opensearch_dashboards.keystore':
      ensure  => absent,
      require => Package['fortishield-dashboard'],
      before  => Service['fortishield-dashboard'],
    }
  }

  service { 'fortishield-dashboard':
    ensure     => running,
    enable     => true,
    hasrestart => true,
    name       => $dashboard_service,
  }
}
