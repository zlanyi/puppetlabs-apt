# Class: apt
#
# This module manages the initial configuration of apt.
#
# Parameters:
#   The parameters listed here are not required in general and were
#     added for use cases related to development environments.
#   disable_keys - disables the requirement for all packages to be signed
#   always_apt_update - rather apt should be updated on every run (intended
#     for development environments where package updates are frequent)
#   purge_sources_list - Accepts true or false. Defaults to false If set to
#     true, Puppet will purge all unmanaged entries from sources.list
#   purge_sources_list_d - Accepts true or false. Defaults to false. If set
#     to true, Puppet will purge all unmanaged entries from sources.list.d
#   update_timeout - Overrides the exec timeout in seconds for apt-get update.
#     If not set defaults to Exec's default (300)
#   update_tries - Number of times that `apt-get update` will be tried. Use this
#     to work around transient DNS and HTTP errors. By default, the command
#     will only be run once.
#
# Actions:
#
# Requires:
#   puppetlabs/stdlib
# Sample Usage:
#  class { 'apt': }

class apt(
  $always_apt_update    = false,
  $disable_keys         = undef,
  $proxy_host           = undef,
  $proxy_port           = '8080',
  $purge_sources_list   = false,
  $purge_sources_list_d = false,
  $purge_preferences    = false,
  $purge_preferences_d  = false,
  $update_timeout       = undef,
  $update_tries         = undef,
  $sources              = undef
) {

  if $::osfamily != 'Debian' {
    fail('This module only works on Debian or derivatives like Ubuntu')
  }

  include apt::params
  include apt::update

  validate_bool($purge_sources_list, $purge_sources_list_d,
                $purge_preferences, $purge_preferences_d)

  $sources_list_content = $purge_sources_list ? {
    false => undef,
    true  => "# Repos managed by puppet.\n",
  }

  if $always_apt_update == true {
    Exec <| title=='apt_update' |> {
      refreshonly => false,
    }
  }

  $root           = $apt::params::root
  $apt_conf_d     = $apt::params::apt_conf_d
  $sources_list_d = $apt::params::sources_list_d
  $preferences_d  = $apt::params::preferences_d
  $provider       = $apt::params::provider

  file { 'sources.list':
    ensure  => present,
    path    => "${root}/sources.list",
    owner   => root,
    group   => root,
    mode    => '0644',
    content => $sources_list_content,
    notify  => Exec['apt_update'],
  }

  file { 'sources.list.d':
    ensure  => directory,
    path    => $sources_list_d,
    owner   => root,
    group   => root,
    purge   => $purge_sources_list_d,
    recurse => $purge_sources_list_d,
    notify  => Exec['apt_update'],
  }

  if $purge_preferences {
    file { 'apt-preferences':
      ensure  => absent,
      path    => "${root}/preferences",
    }
  }

  file { 'preferences.d':
    ensure  => directory,
    path    => $preferences_d,
    owner   => root,
    group   => root,
    purge   => $purge_preferences_d,
    recurse => $purge_preferences_d,
  }

  case $disable_keys {
    true: {
      file { '99unauth':
        ensure  => present,
        content => "APT::Get::AllowUnauthenticated 1;\n",
        path    => "${apt_conf_d}/99unauth",
      }
    }
    false: {
      file { '99unauth':
        ensure => absent,
        path   => "${apt_conf_d}/99unauth",
      }
    }
    undef:   { } # do nothing
    default: { fail('Valid values for disable_keys are true or false') }
  }

  case $proxy_host {
    false, '', undef: {
      file { '01proxy':
        ensure  => absent,
        path    => "${apt_conf_d}/01proxy",
        notify  => Exec['apt_update'],
      }
    }
    default: {
      file { '01proxy':
        ensure  => present,
        path    => "${apt_conf_d}/01proxy",
        content => "Acquire::http::Proxy \"http://${proxy_host}:${proxy_port}\";\n",
        notify  => Exec['apt_update'],
        mode    => '0644',
        owner   => root,
        group   => root,
      }
    }
  }

  file { 'old-proxy-file':
    ensure  => absent,
    path    => "${apt_conf_d}/proxy",
    notify  => Exec['apt_update'],
  }

  # Need anchor to provide containment for dependencies.
  anchor { 'apt::update':
    require => Class['apt::update'],
  }

  # manage sources if present
  if $sources != undef {
    validate_hash($sources)
    create_resources('apt::source', $sources)
  }
}
