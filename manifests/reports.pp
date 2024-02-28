# Copyright (C) 2015, Fortishield Inc.
#Define for a Reports section
define fortishield::reports(
  Optional[String] $r_group               = undef,
  Optional[String] $r_category            = undef,
  Optional[Integer] $r_rule               = undef,
  Optional[Integer[1,16]] $r_level        = undef,
  Optional[String] $r_location            = undef,
  Optional[String] $r_srcip               = undef,
  Optional[String] $r_user                = undef,
  String $r_title                         = '',
  $r_email_to                             = '',
  Optional[Enum['yes', 'no']] $r_showlogs = undef,
) {

  require fortishield::params_manager

  concat::fragment { $name:
    target  => 'manager_ossec.conf',
    order   => 70,
    content => template('fortishield/fragments/_reports.erb')
  }
}
