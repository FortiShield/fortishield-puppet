# Copyright (C) 2015, Fortishield Inc.
#Define a log-file to add to ossec
define fortishield::addlog(
  $logfile      = undef,
  $logtype      = 'syslog',
  $logcommand   = undef,
  $commandalias = undef,
  $frequency    = undef,
  $target_arg   = 'manager_ossec.conf',
) {
  require fortishield::params_manager

  concat::fragment { "ossec.conf_localfile-${logfile}":
    target  => $target_arg,
    content => template('fortishield/fragments/_localfile_generation.erb'),
    order   => 21,
  }

}
