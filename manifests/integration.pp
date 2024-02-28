# Copyright (C) 2015, Fortishield Inc.
#Define for a specific ossec integration
define fortishield::integration(
  $hook_url = '',
  $api_key = '',
  $in_rule_id = '',
  $in_level = 7,
  $in_group = '',
  $in_location = '',
  $in_format = '',
  $in_max_log = '',
) {

  require fortishield::params_manager

  concat::fragment { $name:
    target  => 'manager_ossec.conf',
    order   => 60,
    content => template('fortishield/fragments/_integration.erb')
  }
}
