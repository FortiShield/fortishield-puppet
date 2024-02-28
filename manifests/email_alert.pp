# Copyright (C) 2015, Fortishield Inc.
# Define an email alert
define fortishield::email_alert(
  $alert_email,
  $alert_group    = false,
  $target_arg     = 'manager_ossec.conf',
  $level          = false,
  $event_location = false,
  $format         = false,
  $rule_id        = false,
  $do_not_delay   = false,
  $do_not_group   = false
) {
  require fortishield::params_manager

  concat::fragment { $name:
    target  => $target_arg,
    order   => 66,
    content => template('fortishield/fragments/_email_alert.erb'),
  }
}
