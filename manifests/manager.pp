# Copyright (C) 2015, Fortishield Inc.
# Main ossec server config
class fortishield::manager (

    # Installation

      $server_package_version           = $fortishield::params_manager::server_package_version,
      $manage_firewall                  = $fortishield::params_manager::manage_firewall,


    ### Ossec.conf blocks

      ## Global

      $ossec_logall                     = $fortishield::params_manager::ossec_logall,
      $ossec_logall_json                = $fortishield::params_manager::ossec_logall_json,
      $ossec_emailnotification          = $fortishield::params_manager::ossec_emailnotification,
      $ossec_emailto                    = $fortishield::params_manager::ossec_emailto,
      $ossec_smtp_server                = $fortishield::params_manager::ossec_smtp_server,
      $ossec_emailfrom                  = $fortishield::params_manager::ossec_emailfrom,
      $ossec_email_maxperhour           = $fortishield::params_manager::ossec_email_maxperhour,
      $ossec_email_log_source           = $fortishield::params_manager::ossec_email_log_source,
      $ossec_email_idsname              = $fortishield::params_manager::ossec_email_idsname,
      $ossec_white_list                 = $fortishield::params_manager::ossec_white_list,
      $ossec_alert_level                = $fortishield::params_manager::ossec_alert_level,
      $ossec_email_alert_level          = $fortishield::params_manager::ossec_email_alert_level,
      $ossec_remote_connection          = $fortishield::params_manager::ossec_remote_connection,
      $ossec_remote_port                = $fortishield::params_manager::ossec_remote_port,
      $ossec_remote_protocol            = $fortishield::params_manager::ossec_remote_protocol,
      $ossec_remote_local_ip            = $fortishield::params_manager::ossec_remote_local_ip,
      $ossec_remote_allowed_ips         = $fortishield::params_manager::ossec_remote_allowed_ips,
      $ossec_remote_queue_size          = $fortishield::params_manager::ossec_remote_queue_size,

      # ossec.conf generation parameters

      $configure_rootcheck                  = $fortishield::params_manager::configure_rootcheck,
      $configure_wodle_openscap             = $fortishield::params_manager::configure_wodle_openscap,
      $configure_wodle_cis_cat              = $fortishield::params_manager::configure_wodle_cis_cat,
      $configure_wodle_osquery              = $fortishield::params_manager::configure_wodle_osquery,
      $configure_wodle_syscollector         = $fortishield::params_manager::configure_wodle_syscollector,
      $configure_wodle_docker_listener      = $fortishield::params_manager::configure_wodle_docker_listener,
      $configure_vulnerability_detection    = $fortishield::params_manager::configure_vulnerability_detection,
      $configure_vulnerability_indexer      = $fortishield::params_manager::configure_vulnerability_indexer,
      $configure_sca                        = $fortishield::params_manager::configure_sca,
      $configure_syscheck                   = $fortishield::params_manager::configure_syscheck,
      $configure_command                    = $fortishield::params_manager::configure_command,
      $configure_localfile                  = $fortishield::params_manager::configure_localfile,
      $configure_ruleset                    = $fortishield::params_manager::configure_ruleset,
      $configure_auth                       = $fortishield::params_manager::configure_auth,
      $configure_cluster                    = $fortishield::params_manager::configure_cluster,
      $configure_active_response            = $fortishield::params_manager::configure_active_response,

    # ossec.conf templates paths
      $ossec_manager_template                       = $fortishield::params_manager::ossec_manager_template,
      $ossec_rootcheck_template                     = $fortishield::params_manager::ossec_rootcheck_template,
      $ossec_wodle_openscap_template                = $fortishield::params_manager::ossec_wodle_openscap_template,
      $ossec_wodle_cis_cat_template                 = $fortishield::params_manager::ossec_wodle_cis_cat_template,
      $ossec_wodle_osquery_template                 = $fortishield::params_manager::ossec_wodle_osquery_template,
      $ossec_wodle_syscollector_template            = $fortishield::params_manager::ossec_wodle_syscollector_template,
      $ossec_wodle_docker_listener_template         = $fortishield::params_manager::ossec_wodle_docker_listener_template,
      $ossec_vulnerability_detection_template       = $fortishield::params_manager::ossec_vulnerability_detection_template,
      $ossec_vulnerability_indexer_template         = $fortishield::params_manager::ossec_vulnerability_indexer_template,
      $ossec_sca_template                           = $fortishield::params_manager::ossec_sca_template,
      $ossec_syscheck_template                      = $fortishield::params_manager::ossec_syscheck_template,
      $ossec_default_commands_template              = $fortishield::params_manager::ossec_default_commands_template,
      $ossec_localfile_template                     = $fortishield::params_manager::ossec_localfile_template,
      $ossec_ruleset_template                       = $fortishield::params_manager::ossec_ruleset_template,
      $ossec_auth_template                          = $fortishield::params_manager::ossec_auth_template,
      $ossec_cluster_template                       = $fortishield::params_manager::ossec_cluster_template,
      $ossec_active_response_template               = $fortishield::params_manager::ossec_active_response_template,
      $ossec_syslog_output_template                 = $fortishield::params_manager::ossec_syslog_output_template,

      # active-response
      $ossec_active_response_command                =  $fortishield::params_manager::active_response_command,
      $ossec_active_response_location               =  $fortishield::params_manager::active_response_location,
      $ossec_active_response_level                  =  $fortishield::params_manager::active_response_level,
      $ossec_active_response_agent_id               =  $fortishield::params_manager::active_response_agent_id,
      $ossec_active_response_rules_id               =  $fortishield::params_manager::active_response_rules_id,
      $ossec_active_response_timeout                =  $fortishield::params_manager::active_response_timeout,
      $ossec_active_response_repeated_offenders     =  $fortishield::params_manager::active_response_repeated_offenders,


      ## Rootcheck

      $ossec_rootcheck_disabled             = $fortishield::params_manager::ossec_rootcheck_disabled,
      $ossec_rootcheck_check_files          = $fortishield::params_manager::ossec_rootcheck_check_files,
      $ossec_rootcheck_check_trojans        = $fortishield::params_manager::ossec_rootcheck_check_trojans,
      $ossec_rootcheck_check_dev            = $fortishield::params_manager::ossec_rootcheck_check_dev,
      $ossec_rootcheck_check_sys            = $fortishield::params_manager::ossec_rootcheck_check_sys,
      $ossec_rootcheck_check_pids           = $fortishield::params_manager::ossec_rootcheck_check_pids,
      $ossec_rootcheck_check_ports          = $fortishield::params_manager::ossec_rootcheck_check_ports,
      $ossec_rootcheck_check_if             = $fortishield::params_manager::ossec_rootcheck_check_if,
      $ossec_rootcheck_frequency            = $fortishield::params_manager::ossec_rootcheck_frequency,
      $ossec_rootcheck_ignore_list          = $fortishield::params_manager::ossec_rootcheck_ignore_list,
      $ossec_rootcheck_ignore_sregex_list   = $fortishield::params_manager::ossec_rootcheck_ignore_sregex_list,
      $ossec_rootcheck_rootkit_files        = $fortishield::params_manager::ossec_rootcheck_rootkit_files,
      $ossec_rootcheck_rootkit_trojans      = $fortishield::params_manager::ossec_rootcheck_rootkit_trojans,
      $ossec_rootcheck_skip_nfs             = $fortishield::params_manager::ossec_rootcheck_skip_nfs,
      $ossec_rootcheck_system_audit         = $fortishield::params_manager::ossec_rootcheck_system_audit,

      # SCA

      ## Amazon
      $sca_amazon_enabled = $fortishield::params_manager::sca_amazon_enabled,
      $sca_amazon_scan_on_start = $fortishield::params_manager::sca_amazon_scan_on_start,
      $sca_amazon_interval = $fortishield::params_manager::sca_amazon_interval,
      $sca_amazon_skip_nfs = $fortishield::params_manager::sca_amazon_skip_nfs,
      $sca_amazon_policies = $fortishield::params_manager::sca_amazon_policies,

      ## RHEL
      $sca_rhel_enabled = $fortishield::params_manager::sca_rhel_enabled,
      $sca_rhel_scan_on_start = $fortishield::params_manager::sca_rhel_scan_on_start,
      $sca_rhel_interval = $fortishield::params_manager::sca_rhel_interval,
      $sca_rhel_skip_nfs = $fortishield::params_manager::sca_rhel_skip_nfs,
      $sca_rhel_policies = $fortishield::params_manager::sca_rhel_policies,

      ## <Linux else>
      $sca_else_enabled = $fortishield::params_manager::sca_else_enabled,
      $sca_else_scan_on_start = $fortishield::params_manager::sca_else_scan_on_start,
      $sca_else_interval = $fortishield::params_manager::sca_else_interval,
      $sca_else_skip_nfs = $fortishield::params_manager::sca_else_skip_nfs,
      $sca_else_policies = $fortishield::params_manager::sca_else_policies,


      ## Wodles

      #openscap
      $wodle_openscap_disabled              = $fortishield::params_manager::wodle_openscap_disabled,
      $wodle_openscap_timeout               = $fortishield::params_manager::wodle_openscap_timeout,
      $wodle_openscap_interval              = $fortishield::params_manager::wodle_openscap_interval,
      $wodle_openscap_scan_on_start         = $fortishield::params_manager::wodle_openscap_scan_on_start,

      #cis-cat
      $wodle_ciscat_disabled                = $fortishield::params_manager::wodle_ciscat_disabled,
      $wodle_ciscat_timeout                 = $fortishield::params_manager::wodle_ciscat_timeout,
      $wodle_ciscat_interval                = $fortishield::params_manager::wodle_ciscat_interval,
      $wodle_ciscat_scan_on_start           = $fortishield::params_manager::wodle_ciscat_scan_on_start,
      $wodle_ciscat_java_path               = $fortishield::params_manager::wodle_ciscat_java_path,
      $wodle_ciscat_ciscat_path             = $fortishield::params_manager::wodle_ciscat_ciscat_path,

      #osquery
      $wodle_osquery_disabled               = $fortishield::params_manager::wodle_osquery_disabled,
      $wodle_osquery_run_daemon             = $fortishield::params_manager::wodle_osquery_run_daemon,
      $wodle_osquery_log_path               = $fortishield::params_manager::wodle_osquery_log_path,
      $wodle_osquery_config_path            = $fortishield::params_manager::wodle_osquery_config_path,
      $wodle_osquery_add_labels             = $fortishield::params_manager::wodle_osquery_add_labels,

      #syscollector
      $wodle_syscollector_disabled          = $fortishield::params_manager::wodle_syscollector_disabled,
      $wodle_syscollector_interval          = $fortishield::params_manager::wodle_syscollector_interval,
      $wodle_syscollector_scan_on_start     = $fortishield::params_manager::wodle_syscollector_scan_on_start,
      $wodle_syscollector_hardware          = $fortishield::params_manager::wodle_syscollector_hardware,
      $wodle_syscollector_os                = $fortishield::params_manager::wodle_syscollector_os,
      $wodle_syscollector_network           = $fortishield::params_manager::wodle_syscollector_network,
      $wodle_syscollector_packages          = $fortishield::params_manager::wodle_syscollector_packages,
      $wodle_syscollector_ports             = $fortishield::params_manager::wodle_syscollector_ports,
      $wodle_syscollector_processes         = $fortishield::params_manager::wodle_syscollector_processes,

      #docker-listener
      $wodle_docker_listener_disabled       = $fortishield::params_manager::wodle_docker_listener_disabled,

      #vulnerability-detection
      $vulnerability_detection_enabled                  = $fortishield::params_manager::vulnerability_detection_enabled,
      $vulnerability_detection_index_status             = $fortishield::params_manager::vulnerability_detection_index_status,
      $vulnerability_detection_feed_update_interval     = $fortishield::params_manager::vulnerability_detection_feed_update_interval,

      #vulnerability-indexer
      $vulnerability_indexer_enabled            = $fortishield::params_manager::vulnerability_indexer_enabled,
      $vulnerability_indexer_hosts_host         = $fortishield::params_manager::vulnerability_indexer_hosts_host,
      $vulnerability_indexer_hosts_port         = $fortishield::params_manager::vulnerability_indexer_hosts_port,
      $vulnerability_indexer_username           = $fortishield::params_manager::vulnerability_indexer_username,
      $vulnerability_indexer_password           = $fortishield::params_manager::vulnerability_indexer_password,
      $vulnerability_indexer_ssl_ca             = $fortishield::params_manager::vulnerability_indexer_ssl_ca,
      $vulnerability_indexer_ssl_certificate    = $fortishield::params_manager::vulnerability_indexer_ssl_certificate,
      $vulnerability_indexer_ssl_key            = $fortishield::params_manager::vulnerability_indexer_ssl_key,

      # syslog
      $syslog_output                        = $fortishield::params_manager::syslog_output,
      $syslog_output_level                  = $fortishield::params_manager::syslog_output_level,
      $syslog_output_port                   = $fortishield::params_manager::syslog_output_port,
      $syslog_output_server                 = $fortishield::params_manager::syslog_output_server,
      $syslog_output_format                 = $fortishield::params_manager::syslog_output_format,

      # Authd configuration
      $ossec_auth_disabled                  = $fortishield::params_manager::ossec_auth_disabled,
      $ossec_auth_port                      = $fortishield::params_manager::ossec_auth_port,
      $ossec_auth_use_source_ip             = $fortishield::params_manager::ossec_auth_use_source_ip,
      $ossec_auth_force_enabled             = $fortishield::params_manager::ossec_auth_force_enabled,
      $ossec_auth_force_key_mismatch        = $fortishield::params_manager::ossec_auth_force_key_mismatch,
      $ossec_auth_force_disc_time           = $fortishield::params_manager::ossec_auth_force_disc_time,
      $ossec_auth_force_after_reg_time      = $fortishield::params_manager::ossec_auth_force_after_reg_time,
      $ossec_auth_purgue                    = $fortishield::params_manager::ossec_auth_purgue,
      $ossec_auth_use_password              = $fortishield::params_manager::ossec_auth_use_password,
      $ossec_auth_limit_maxagents           = $fortishield::params_manager::ossec_auth_limit_maxagents,
      $ossec_auth_ciphers                   = $fortishield::params_manager::ossec_auth_ciphers,
      $ossec_auth_ssl_verify_host           = $fortishield::params_manager::ossec_auth_ssl_verify_host,
      $ossec_auth_ssl_manager_cert          = $fortishield::params_manager::ossec_auth_ssl_manager_cert,
      $ossec_auth_ssl_manager_key           = $fortishield::params_manager::ossec_auth_ssl_manager_key,
      $ossec_auth_ssl_auto_negotiate        = $fortishield::params_manager::ossec_auth_ssl_auto_negotiate,


      # syscheck
      $ossec_syscheck_disabled              = $fortishield::params_manager::ossec_syscheck_disabled,
      $ossec_syscheck_frequency             = $fortishield::params_manager::ossec_syscheck_frequency,
      $ossec_syscheck_scan_on_start         = $fortishield::params_manager::ossec_syscheck_scan_on_start,
      $ossec_syscheck_auto_ignore           = $fortishield::params_manager::ossec_syscheck_auto_ignore,
      $ossec_syscheck_directories_1         = $fortishield::params_manager::ossec_syscheck_directories_1,
      $ossec_syscheck_directories_2         = $fortishield::params_manager::ossec_syscheck_directories_2,
      $ossec_syscheck_whodata_directories_1            = $fortishield::params_manager::ossec_syscheck_whodata_directories_1,
      $ossec_syscheck_realtime_directories_1           = $fortishield::params_manager::ossec_syscheck_realtime_directories_1,
      $ossec_syscheck_whodata_directories_2            = $fortishield::params_manager::ossec_syscheck_whodata_directories_2,
      $ossec_syscheck_realtime_directories_2           = $fortishield::params_manager::ossec_syscheck_realtime_directories_2,
      $ossec_syscheck_ignore_list           = $fortishield::params_manager::ossec_syscheck_ignore_list,

      $ossec_syscheck_ignore_type_1         = $fortishield::params_manager::ossec_syscheck_ignore_type_1,
      $ossec_syscheck_ignore_type_2         = $fortishield::params_manager::ossec_syscheck_ignore_type_2,
      $ossec_syscheck_process_priority             = $fortishield::params_manager::ossec_syscheck_process_priority,
      $ossec_syscheck_synchronization_enabled      = $fortishield::params_manager::ossec_syscheck_synchronization_enabled,
      $ossec_syscheck_synchronization_interval     = $fortishield::params_manager::ossec_syscheck_synchronization_interval,
      $ossec_syscheck_synchronization_max_eps      = $fortishield::params_manager::ossec_syscheck_synchronization_max_eps,
      $ossec_syscheck_synchronization_max_interval = $fortishield::params_manager::ossec_syscheck_synchronization_max_interval,

      $ossec_syscheck_nodiff                = $fortishield::params_manager::ossec_syscheck_nodiff,
      $ossec_syscheck_skip_nfs              = $fortishield::params_manager::ossec_syscheck_skip_nfs,

      # Cluster

      $ossec_cluster_name                   = $fortishield::params_manager::ossec_cluster_name,
      $ossec_cluster_node_name              = $fortishield::params_manager::ossec_cluster_node_name,
      $ossec_cluster_node_type              = $fortishield::params_manager::ossec_cluster_node_type,
      $ossec_cluster_key                    = $fortishield::params_manager::ossec_cluster_key,
      $ossec_cluster_port                   = $fortishield::params_manager::ossec_cluster_port,
      $ossec_cluster_bind_addr              = $fortishield::params_manager::ossec_cluster_bind_addr,
      $ossec_cluster_nodes                  = $fortishield::params_manager::ossec_cluster_nodes,
      $ossec_cluster_hidden                 = $fortishield::params_manager::ossec_cluster_hidden,
      $ossec_cluster_disabled               = $fortishield::params_manager::ossec_cluster_disabled,

      #----- End of ossec.conf parameters -------

      $ossec_cluster_enable_firewall        = $fortishield::params_manager::ossec_cluster_enable_firewall,

      $ossec_prefilter                      = $fortishield::params_manager::ossec_prefilter,
      $ossec_integratord_enabled            = $fortishield::params_manager::ossec_integratord_enabled,

      $manage_client_keys                   = $fortishield::params_manager::manage_client_keys,
      $agent_auth_password                  = $fortishield::params_manager::agent_auth_password,
      $ar_repeated_offenders                = $fortishield::params_manager::ar_repeated_offenders,

      $local_decoder_template               = $fortishield::params_manager::local_decoder_template,
      $decoder_exclude                      = $fortishield::params_manager::decoder_exclude,
      $local_rules_template                 = $fortishield::params_manager::local_rules_template,
      $rule_exclude                         = $fortishield::params_manager::rule_exclude,
      $shared_agent_template                = $fortishield::params_manager::shared_agent_template,

      $fortishield_manager_verify_manager_ssl     = $fortishield::params_manager::fortishield_manager_verify_manager_ssl,
      $fortishield_manager_server_crt             = $fortishield::params_manager::fortishield_manager_server_crt,
      $fortishield_manager_server_key             = $fortishield::params_manager::fortishield_manager_server_key,

      $ossec_local_files                    = $::fortishield::params_manager::default_local_files,

      # API


      $fortishield_api_host                           = $fortishield::params_manager::fortishield_api_host,

      $fortishield_api_port                           = $fortishield::params_manager::fortishield_api_port,
      $fortishield_api_file                           = $fortishield::params_manager::fortishield_api_file,

      $fortishield_api_https_enabled                  = $fortishield::params_manager::fortishield_api_https_enabled,
      $fortishield_api_https_key                      = $fortishield::params_manager::fortishield_api_https_key,

      $fortishield_api_https_cert                     = $fortishield::params_manager::fortishield_api_https_cert,
      $fortishield_api_https_use_ca                   = $fortishield::params_manager::fortishield_api_https_use_ca,
      $fortishield_api_https_ca                       = $fortishield::params_manager::fortishield_api_https_ca,
      $fortishield_api_logs_level                     = $fortishield::params_manager::fortishield_api_logs_level,
      $fortishield_api_logs_format                    = $fortishield::params_manager::fortishield_api_logs_format,
      $fortishield_api_ssl_ciphers                    = $fortishield::params_manager::fortishield_api_ssl_ciphers,
      $fortishield_api_ssl_protocol                   = $fortishield::params_manager::fortishield_api_ssl_protocol,

      $fortishield_api_cors_enabled                   = $fortishield::params_manager::fortishield_api_cors_enabled,
      $fortishield_api_cors_source_route              = $fortishield::params_manager::fortishield_api_cors_source_route,
      $fortishield_api_cors_expose_headers            = $fortishield::params_manager::fortishield_api_cors_expose_headers,


      $fortishield_api_cors_allow_credentials         = $::fortishield::params_manager::fortishield_api_cors_allow_credentials,
      $fortishield_api_cache_enabled                  = $::fortishield::params_manager::fortishield_api_cache_enabled,

      $fortishield_api_cache_time                     = $::fortishield::params_manager::fortishield_api_cache_time,

      $fortishield_api_access_max_login_attempts      = $::fortishield::params_manager::fortishield_api_access_max_login_attempts,
      $fortishield_api_access_block_time              = $::fortishield::params_manager::fortishield_api_access_block_time,
      $fortishield_api_access_max_request_per_minute  = $::fortishield::params_manager::fortishield_api_access_max_request_per_minute,
      $fortishield_api_drop_privileges                = $::fortishield::params_manager::fortishield_api_drop_privileges,
      $fortishield_api_experimental_features          = $::fortishield::params_manager::fortishield_api_experimental_features,

      $remote_commands_localfile                = $::fortishield::params_manager::remote_commands_localfile,
      $remote_commands_localfile_exceptions     = $::fortishield::params_manager::remote_commands_localfile_exceptions,
      $remote_commands_wodle                    = $::fortishield::params_manager::remote_commands_wodle,
      $remote_commands_wodle_exceptions         = $::fortishield::params_manager::remote_commands_wodle_exceptions,
      $limits_eps                               = $::fortishield::params_manager::limits_eps,

      $fortishield_api_template                       = $::fortishield::params_manager::fortishield_api_template,




) inherits fortishield::params_manager {
  validate_legacy(
    Boolean, 'validate_bool', $syslog_output,$fortishield_manager_verify_manager_ssl
  )
  validate_legacy(
    Array, 'validate_array', $decoder_exclude, $rule_exclude
  )

  ## Determine which kernel and family puppet is running on. Will be used on _localfile, _rootcheck, _syscheck & _sca

  if ($::kernel == 'windows') {
    $kernel = 'Linux'

  }else{
    $kernel = 'Linux'
    if ($::osfamily == 'Debian'){
      $os_family = 'debian'
    }else{
      $os_family = 'centos'
    }
  }


  if ( $ossec_syscheck_whodata_directories_1 == 'yes' ) or ( $ossec_syscheck_whodata_directories_2 == 'yes' ) {
    case $::operatingsystem {
      'Debian', 'debian', 'Ubuntu', 'ubuntu': {
        package { 'Installing Auditd...':
          name => 'auditd',
        }
      }
      default: {
        package { 'Installing Audit...':
          name => 'audit'
        }
      }
    }
    service { 'auditd':
      ensure => running,
      enable => true,
    }
  }

  # This allows arrays of integers, sadly
  # (commented due to stdlib version requirement)
  validate_legacy(Boolean, 'validate_bool', $ossec_emailnotification)
  if ($ossec_emailnotification) {
    if $ossec_smtp_server == undef {
      fail('$ossec_emailnotification is enabled but $smtp_server was not set')
    }
    validate_legacy(String, 'validate_string', $ossec_smtp_server)
    validate_legacy(String, 'validate_string', $ossec_emailfrom)
    validate_legacy(Array, 'validate_array', $ossec_emailto)
  }

  if $::osfamily == 'windows' {
    fail('The ossec module does not yet support installing the OSSEC HIDS server on Windows')
  }

  # Install and configure Fortishield-manager package

  package { $fortishield::params_manager::server_package:
    ensure  => $server_package_version, # lint:ignore:security_package_pinned_version
  }

  file {
    default:
      owner   => $fortishield::params_manager::config_owner,
      group   => $fortishield::params_manager::config_group,
      mode    => $fortishield::params_manager::config_mode,
      notify  => Service[$fortishield::params_manager::server_service],
      require => Package[$fortishield::params_manager::server_package];
    $fortishield::params_manager::shared_agent_config_file:
      validate_cmd => $fortishield::params_manager::validate_cmd_conf,
      content      => template($shared_agent_template);
    '/var/ossec/etc/rules/local_rules.xml':
      content      => template($local_rules_template);
    '/var/ossec/etc/decoders/local_decoder.xml':
      content      => template($local_decoder_template);
    $fortishield::params_manager::processlist_file:
      content      => template('fortishield/process_list.erb');
  }

  service { $fortishield::params_manager::server_service:
    ensure    => running,
    enable    => true,
    hasstatus => $fortishield::params_manager::service_has_status,
    pattern   => $fortishield::params_manager::server_service,
    provider  => $fortishield::params_manager::ossec_service_provider,
    require   => Package[$fortishield::params_manager::server_package],
  }

  ## Declaring variables for localfile and wodles generation

  case $::operatingsystem{
    'RedHat', 'OracleLinux':{
      $apply_template_os = 'rhel'
      if ( $::operatingsystemrelease =~ /^9.*/ ){
        $rhel_version = '9'
      }elsif ( $::operatingsystemrelease =~ /^8.*/ ){
        $rhel_version = '8'
      }elsif ( $::operatingsystemrelease =~ /^7.*/ ){
        $rhel_version = '7'
      }elsif ( $::operatingsystemrelease =~ /^6.*/ ){
        $rhel_version = '6'
      }elsif ( $::operatingsystemrelease =~ /^5.*/ ){
        $rhel_version = '5'
      }else{
        fail('This ossec module has not been tested on your distribution')
      }
    }'Debian', 'debian', 'Ubuntu', 'ubuntu':{
      $apply_template_os = 'debian'
      if ( $::lsbdistcodename == 'wheezy') or ($::lsbdistcodename == 'jessie'){
        $debian_additional_templates = 'yes'
      }
    }'Amazon':{
      $apply_template_os = 'amazon'
    }'CentOS','Centos','centos':{
      $apply_template_os = 'centos'
    }
    default: { fail('This ossec module has not been tested on your distribution') }
  }



  concat { 'manager_ossec.conf':
    path    => $fortishield::params_manager::config_file,
    owner   => $fortishield::params_manager::config_owner,
    group   => $fortishield::params_manager::config_group,
    mode    => $fortishield::params_manager::config_mode,
    require => Package[$fortishield::params_manager::server_package],
    notify  => Service[$fortishield::params_manager::server_service],
  }
  concat::fragment {
    'ossec.conf_header':
      target  => 'manager_ossec.conf',
      order   => 00,
      content => "<ossec_config>\n";
    'ossec.conf_main':
      target  => 'manager_ossec.conf',
      order   => 01,
      content => template($ossec_manager_template);
  }

  if ($syslog_output == true){
    concat::fragment {
      'ossec.conf_syslog_output':
        target  => 'manager_ossec.conf',
        content => template($ossec_syslog_output_template);
    }
  }

  if($configure_rootcheck == true){
    concat::fragment {
        'ossec.conf_rootcheck':
          order   => 10,
          target  => 'manager_ossec.conf',
          content => template($ossec_rootcheck_template);
      }
  }

  if ($configure_wodle_openscap == true){
    concat::fragment {
      'ossec.conf_wodle_openscap':
        order   => 15,
        target  => 'manager_ossec.conf',
        content => template($ossec_wodle_openscap_template);
    }
  }
  if ($configure_wodle_cis_cat == true){
    concat::fragment {
      'ossec.conf_wodle_ciscat':
        order   => 20,
        target  => 'manager_ossec.conf',
        content => template($ossec_wodle_cis_cat_template);
    }
  }
  if ($configure_wodle_osquery== true){
    concat::fragment {
      'ossec.conf_wodle_osquery':
        order   => 25,
        target  => 'manager_ossec.conf',
        content => template($ossec_wodle_osquery_template);
    }
  }
  if ($configure_wodle_syscollector == true){
    concat::fragment {
      'ossec.conf_wodle_syscollector':
        order   => 30,
        target  => 'manager_ossec.conf',
        content => template($ossec_wodle_syscollector_template);
    }
  }
  if ($configure_wodle_docker_listener == true){
    concat::fragment {
      'ossec.conf_wodle_docker_listener':
        order   => 30,
        target  => 'manager_ossec.conf',
        content => template($ossec_wodle_docker_listener_template);
    }
  }
  if ($configure_sca == true){
    concat::fragment {
      'ossec.conf_sca':
        order   => 40,
        target  => 'manager_ossec.conf',
        content => template($ossec_sca_template);
      }
  }
  if($configure_vulnerability_detection == true){
    concat::fragment {
      'ossec.conf_vulnerability_detection':
        order   => 45,
        target  => 'manager_ossec.conf',
        content => template($ossec_vulnerability_detection_template);
    }
  }
  if($configure_vulnerability_detection == true) or ($configure_vulnerability_indexer == true){
    concat::fragment {
      'ossec.conf_vulnerability_indexer':
        order   => 49,
        target  => 'manager_ossec.conf',
        content => template($ossec_vulnerability_indexer_template);
    }
  }
  if($configure_syscheck == true){
    concat::fragment {
      'ossec.conf_syscheck':
        order   => 55,
        target  => 'manager_ossec.conf',
        content => template($ossec_syscheck_template);
    }
  }
  if ($configure_command == true){
    concat::fragment {
          'ossec.conf_command':
            order   => 60,
            target  => 'manager_ossec.conf',
            content => template($ossec_default_commands_template);
      }
  }
  if ($configure_localfile == true){
    concat::fragment {
      'ossec.conf_localfile':
        order   => 65,
        target  => 'manager_ossec.conf',
        content => template($ossec_localfile_template);
    }
  }
  if($configure_ruleset == true){
    concat::fragment {
        'ossec.conf_ruleset':
          order   => 75,
          target  => 'manager_ossec.conf',
          content => template($ossec_ruleset_template);
      }
  }
  if ($configure_auth == true){
    concat::fragment {
        'ossec.conf_auth':
          order   => 80,
          target  => 'manager_ossec.conf',
          content => template($ossec_auth_template);
      }
  }
  if ($configure_cluster == true){
    concat::fragment {
        'ossec.conf_cluster':
          order   => 85,
          target  => 'manager_ossec.conf',
          content => template($ossec_cluster_template);
      }
  }
  if ($configure_active_response == true){
    fortishield::activeresponse { 'active-response configuration':
      active_response_command            => $ossec_active_response_command,
      active_response_location           => $ossec_active_response_location,
      active_response_level              => $ossec_active_response_level,
      active_response_agent_id           => $ossec_active_response_agent_id,
      active_response_rules_id           => $ossec_active_response_rules_id,
      active_response_timeout            => $ossec_active_response_timeout,
      active_response_repeated_offenders => $ossec_active_response_repeated_offenders,
      order_arg                          => 90
    }
  }
  concat::fragment {
    'ossec.conf_footer':
      target  => 'manager_ossec.conf',
      order   => 99,
      content => "</ossec_config>\n";
  }

  exec { 'Generate the fortishield-keystore (username)':
    path    => ['/var/ossec/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin'],
    command => "fortishield-keystore -f indexer -k username -v ${vulnerability_indexer_username}",
  }

  exec { 'Generate the fortishield-keystore (password)':
    path    => ['/var/ossec/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin'],
    command => "fortishield-keystore -f indexer -k password -v ${vulnerability_indexer_password}",
  }

  if ( $manage_client_keys == 'yes') {
    # TODO: ensure the authd service is started if manage_client_keys == authd
    # (see https://github.com/fortishield/fortishield/issues/80)

    file { $fortishield::params_manager::authd_pass_file:
      owner   => $fortishield::params_manager::keys_owner,
      group   => $fortishield::params_manager::keys_group,
      mode    => $fortishield::params_manager::keys_mode,
      content => $agent_auth_password,
      require => Package[$fortishield::params_manager::server_package],
      notify  => Service[$fortishield::params_manager::server_service],
    }
  }

  # https://fortishield.github.io/documentation/current/user-manual/registering/use-registration-service.html#verify-manager-via-ssl
  if $fortishield_manager_verify_manager_ssl {

    if ($fortishield_manager_server_crt != undef) and ($fortishield_manager_server_key != undef) {
      validate_legacy(
        String, 'validate_string', $fortishield_manager_server_crt, $fortishield_manager_server_key
      )

      file { '/var/ossec/etc/sslmanager.key':
        content => $fortishield_manager_server_key,
        owner   => 'root',
        group   => 'fortishield',
        mode    => '0640',
        require => Package[$fortishield::params_manager::server_package],
        notify  => Service[$fortishield::params_manager::server_service],
      }

      file { '/var/ossec/etc/sslmanager.cert':
        content => $fortishield_manager_server_crt,
        owner   => 'root',
        group   => 'fortishield',
        mode    => '0640',
        require => Package[$fortishield::params_manager::server_package],
        notify  => Service[$fortishield::params_manager::server_service],
      }
    }
  }

  # Manage firewall
  if $manage_firewall == true {
    include firewall
    firewall { '1514 fortishield-manager':
      dport  => $ossec_remote_port,
      proto  => $ossec_remote_protocol,
      action => 'accept',
      state  => [
        'NEW',
        'RELATED',
        'ESTABLISHED'],
    }
  }
  if $ossec_cluster_enable_firewall == 'yes'{
    include firewall
    firewall { '1516 fortishield-manager':
      dport  => $ossec_cluster_port,
      proto  => $ossec_remote_protocol,
      action => 'accept',
      state  => [
        'NEW',
        'RELATED',
        'ESTABLISHED'],
    }
  }

  if ( $ossec_syscheck_whodata_directories_1 == 'yes' ) or ( $ossec_syscheck_whodata_directories_2 == 'yes' ) {
    exec { 'Ensure fortishield-fim rule is added to auditctl':
      command => '/sbin/auditctl -l',
      unless  => '/sbin/auditctl -l | grep fortishield_fim',
      tries   => 2
    }
  }

  file { '/var/ossec/api/configuration/api.yaml':
    owner   => 'root',
    group   => 'fortishield',
    mode    => '0640',
    content => template('fortishield/fortishield_api_yml.erb'),
    require => Package[$fortishield::params_manager::server_package],
    notify  => Service[$fortishield::params_manager::server_service]
  }

}
