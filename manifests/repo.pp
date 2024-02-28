# Copyright (C) 2015, Fortishield Inc.
# Fortishield repository installation
class fortishield::repo (
) {

  case $::osfamily {
    'Debian' : {
      if $::lsbdistcodename =~ /(jessie|wheezy|stretch|precise|trusty|vivid|wily|xenial|yakketi|groovy)/
      and ! defined(Package['apt-transport-https']) {
        ensure_packages(['apt-transport-https'], {'ensure' => 'present'})
      }
      # apt-key added by issue #34
      apt::key { 'fortishield':
        id     => '0DCFCA5547B19D2A6099506096B3EE5F29111145',
        source => 'https://packages.fortishield.github.io/key/GPG-KEY-FORTISHIELD',
        server => 'pgp.mit.edu'
      }
      case $::lsbdistcodename {
        /(jessie|wheezy|stretch|buster|bullseye|bookworm|sid|precise|trusty|vivid|wily|xenial|yakketi|bionic|focal|groovy|jammy)/: {

          apt::source { 'fortishield':
            ensure   => present,
            comment  => 'This is the FORTISHIELD Ubuntu repository',
            location => 'https://packages.fortishield.github.io/4.x/apt',
            release  => 'stable',
            repos    => 'main',
            include  => {
              'src' => false,
              'deb' => true,
            },
          }
        }
        default: { fail('This ossec module has not been tested on your distribution (or lsb package not installed)') }
      }
    }
    'Linux', 'RedHat', 'Suse' : {
        case $::os[name] {
          /^(CentOS|RedHat|OracleLinux|Fedora|Amazon|AlmaLinux|Rocky|SLES)$/: {

            if ( $::operatingsystemrelease =~ /^5.*/ ) {
              $baseurl  = 'https://packages.fortishield.github.io/4.x/yum/5/'
              $gpgkey   = 'http://packages.fortishield.github.io/key/GPG-KEY-FORTISHIELD'
            } else {
              $baseurl  = 'https://packages.fortishield.github.io/4.x/yum/'
              $gpgkey   = 'https://packages.fortishield.github.io/key/GPG-KEY-FORTISHIELD'
            }
          }
          default: { fail('This ossec module has not been tested on your distribution.') }
        }
        # Set up OSSEC repo
        case $::os[name] {
          /^(CentOS|RedHat|OracleLinux|Fedora|Amazon|AlmaLinux)$/: {
            yumrepo { 'fortishield':
              descr    => 'FORTISHIELD OSSEC Repository - www.fortishield.github.io',
              enabled  => true,
              gpgcheck => 1,
              gpgkey   => $gpgkey,
              baseurl  => $baseurl
            }
          }
          /^(SLES)$/: {
            zypprepo { 'fortishield':
              ensure        => present,
              name          => 'FORTISHIELD OSSEC Repository - www.fortishield.github.io',
              enabled       => 1,
              gpgcheck      => 0,
              repo_gpgcheck => 0,
              pkg_gpgcheck  => 0,
              gpgkey        => $gpgkey,
              baseurl       => $baseurl
            }
          }
        }
    }
  }
}
