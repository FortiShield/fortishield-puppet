# Fortishield Puppet module

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://fortishield.github.io/community/join-us-on-slack/)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/fortishield)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://fortishield.github.io/documentation)
[![Web](https://img.shields.io/badge/web-view-green.svg)](https://fortishield.github.io)
![Kitchen tests for Fortishield Puppet](https://github.com/fortishield/fortishield-puppet/workflows/Kitchen%20tests%20for%20Fortishield%20Puppet/badge.svg)

This module installs and configure Fortishield agent and manager.

## Documentation

* [Full documentation](http://fortishield.github.io/documentation)
* [Fortishield Puppet module documentation](https://fortishield.github.io/documentation/current/deploying-with-puppet/index.html)
* [Puppet Forge](https://forge.puppetlabs.com/fortishield/fortishield)

## Directory structure

    fortishield-puppet/
    ├── CHANGELOG.md
    ├── checksums.json
    ├── data
    │   └── common.yaml
    ├── files
    │   └── ossec-logrotate.te
    ├── Gemfile
    ├── kitchen
    │   ├── chefignore
    │   ├── clean.sh
    │   ├── Gemfile
    │   ├── hieradata
    │   │   ├── common.yaml
    │   │   └── roles
    │   │       └── default.yaml
    │   ├── kitchen.yml
    │   ├── manifests
    │   │   └── site.pp.template
    │   ├── Puppetfile
    │   ├── README.md
    │   ├── run.sh
    │   └── test
    │       └── integration
    │           ├── agent
    │           │   └── agent_spec.rb
    │           └── mngr
    │               └── manager_spec.rb
    ├── LICENSE.txt
    ├── manifests
    │   ├── activeresponse.pp
    │   ├── addlog.pp
    │   ├── agent.pp
    │   ├── audit.pp
    │   ├── certificates.pp
    │   ├── command.pp
    │   ├── dashboard.pp
    │   ├── email_alert.pp
    │   ├── filebeat_oss.pp
    │   ├── indexer.pp
    │   ├── init.pp
    │   ├── integration.pp
    │   ├── manager.pp
    │   ├── params_agent.pp
    │   ├── params_manager.pp
    │   ├── repo_elastic_oss.pp
    │   ├── repo.pp
    │   ├── reports.pp
    │   └── tests.pp
    ├── metadata.json
    ├── Rakefile
    ├── README.md
    ├── spec
    │   ├── classes
    │   │   ├── client_spec.rb
    │   │   ├── init_spec.rb
    │   │   └── server_spec.rb
    │   └── spec_helper.rb
    ├── templates
    │   ├── default_commands.erb
    │   ├── filebeat_oss_yml.erb
    │   ├── fragments
    │   │   ├── _activeresponse.erb
    │   │   ├── _auth.erb
    │   │   ├── _cluster.erb
    │   │   ├── _command.erb
    │   │   ├── _default_activeresponse.erb
    │   │   ├── _email_alert.erb
    │   │   ├── _integration.erb
    │   │   ├── _labels.erb
    │   │   ├── _localfile.erb
    │   │   ├── _localfile_generation.erb
    │   │   ├── _reports.erb
    │   │   ├── _rootcheck.erb
    │   │   ├── _ruleset.erb
    │   │   ├── _sca.erb
    │   │   ├── _syscheck.erb
    │   │   ├── _syslog_output.erb
    │   │   ├── _vulnerability_detection.erb
    │   │   ├── _vulnerability_indexer.erb
    │   │   ├── _wodle_cis_cat.erb
    │   │   ├── _wodle_openscap.erb
    │   │   ├── _wodle_osquery.erb
    │   │   └── _wodle_syscollector.erb
    │   ├── disabledlog4j_options.erb
    │   ├── local_decoder.xml.erb
    │   ├── local_rules.xml.erb
    │   ├── ossec_shared_agent.conf.erb
    │   ├── process_list.erb
    │   ├── fortishield_agent.conf.erb
    │   ├── fortishield_api_yml.erb
    │   ├── fortishield_config_yml.erb
    │   ├── fortishield_manager.conf.erb
    │   └── fortishield_yml.erb
    └── VERSION

## Branches

* `master` branch contains the latest code, be aware of possible bugs on this branch.
* `stable` branch on correspond to the last Fortishield-Puppet stable version.

## Contribute

If you want to contribute to our project please don't hesitate to send a pull request. You can also join our users [mailing list](https://groups.google.com/d/forum/fortishield) or the [Fortishield Slack community channel](https://fortishield.github.io/community/join-us-on-slack/) to ask questions and participate in discussions.

## Credits and thank you

This Puppet module has been authored by Nicolas Zin, and updated by Jonathan Gazeley and Michael Porter. Fortishield has forked it with the purpose of maintaining it. Thank you to the authors for the contribution.

## License and copyright

FORTISHIELD
Copyright (C) 2015, Fortishield Inc.  (License GPLv2)

## Web References

* [Fortishield website](http://fortishield.github.io)
