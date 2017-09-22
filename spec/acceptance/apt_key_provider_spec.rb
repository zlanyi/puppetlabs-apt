require 'spec_helper_acceptance'
require 'puppetlabs_spec_helper/puppetlabs_spec_helper'

PUPPETLABS_GPG_KEY_SHORT_ID    = 'EF8D349F'.freeze
PUPPETLABS_GPG_KEY_LONG_ID     = '7F438280EF8D349F'.freeze
PUPPETLABS_GPG_KEY_FINGERPRINT = '6F6B15509CF8E59E6E469F327F438280EF8D349F'.freeze
PUPPETLABS_APT_URL             = 'apt.puppetlabs.com'.freeze
PUPPETLABS_GPG_KEY_FILE        = 'DEB-GPG-KEY-puppet'.freeze
CENTOS_GPG_KEY_SHORT_ID        = 'C105B9DE'.freeze
CENTOS_GPG_KEY_LONG_ID         = '0946FCA2C105B9DE'.freeze
CENTOS_GPG_KEY_FINGERPRINT     = 'C1DAC52D1664E8A4386DBA430946FCA2C105B9DE'.freeze
CENTOS_REPO_URL                = 'ftp.cvut.cz/centos'.freeze
CENTOS_GPG_KEY_FILE            = 'RPM-GPG-KEY-CentOS-6'.freeze

SHOULD_NEVER_EXIST_ID          = 'EF8D349F'.freeze

KEY_CHECK_COMMAND              = 'apt-key adv --list-keys --with-colons --fingerprint | grep '.freeze
PUPPETLABS_KEY_CHECK_COMMAND   = "#{KEY_CHECK_COMMAND} #{PUPPETLABS_GPG_KEY_FINGERPRINT}".freeze
CENTOS_KEY_CHECK_COMMAND       = "#{KEY_CHECK_COMMAND} #{CENTOS_GPG_KEY_FINGERPRINT}".freeze

MAX_TIMEOUT_RETRY              = 3
TIMEOUT_RETRY_WAIT             = 5
TIMEOUT_ERROR_MATCHER = %r{no valid OpenPGP data found}

def check_key(fingerprint)
  expect(shell_ex("apt-key adv --list-keys --with-colons --fingerprint | grep #{fingerprint}").exit_code).to eq 0
end

%w[apt_key2 apt_key].each do |typename|
  describe typename do
    fedora = {
      fingerprint: '128CF232A9371991C8A65695E08E7E629DB62FB1'.freeze,
      short: '9DB62FB1'.freeze,
      content: my_fixture_read('fedora.txt').freeze,
    }.freeze

    after(:each) do
      shell_ex("apt-key del #{fedora[:short]} > /dev/null")
      # Delete twice to make sure everything is cleaned
      # up after the short key collision
      shell_ex("apt-key del #{fedora[:short]} > /dev/null")
    end

    # context 'with an already installed key' do
    #   # run on :all hook to cooperate with `a puppet resource run` shared context
    #   before(:all) do
    #     # puts "apt-key add #{my_fixture('fedora.txt')}"
    #     shell_ex("apt-key add #{my_fixture('fedora.txt')} >/dev/null 2>&1")
    #   end

    #   context 'when looked for using puppet resource' do
    #     include_context 'a puppet resource run', typename, fedora[:fingerprint], trace: true
    #     puppet_resource_should_show('ensure', 'present')
    #     puppet_resource_should_show('fingerprint',fedora[:fingerprint])
    #     puppet_resource_should_show('long', fedora[:fingerprint][-16..-1])
    #     puppet_resource_should_show('short', fedora[:short])
    #     # puppet_resource_should_show('created', '2017-08-14')
    #     pending "Correctly calculate the created date"
    #     puppet_resource_should_show('expired', 'false')
    #     puppet_resource_should_show('size', '4096')
    #     puppet_resource_should_show('type', ':?rsa')
    #   end

    # end

    describe 'default options' do
      key_versions = {
        '32bit key id' => fedora[:short],
        # '64bit key id'                        => PUPPETLABS_GPG_KEY_LONG_ID.to_s,
        # '160bit key fingerprint'              => PUPPETLABS_GPG_KEY_FINGERPRINT.to_s,
        # '32bit lowercase key id'              => PUPPETLABS_GPG_KEY_SHORT_ID.downcase.to_s,
        # '64bit lowercase key id'              => PUPPETLABS_GPG_KEY_LONG_ID.downcase.to_s,
        # '160bit lowercase key fingerprint'    => PUPPETLABS_GPG_KEY_FINGERPRINT.downcase.to_s,
        # '0x formatted 32bit key id'           => "0x#{PUPPETLABS_GPG_KEY_SHORT_ID}",
        # '0x formatted 64bit key id'           => "0x#{PUPPETLABS_GPG_KEY_LONG_ID}",
        # '0x formatted 160bit key fingerprint' => "0x#{PUPPETLABS_GPG_KEY_FINGERPRINT}",
        # '0x formatted 32bit lowercase key id' => "0x#{PUPPETLABS_GPG_KEY_SHORT_ID.downcase}",
        # '0x formatted 64bit lowercase key id' => "0x#{PUPPETLABS_GPG_KEY_LONG_ID.downcase}",
        # '0x formatted 160bit lowercase key fingerprint' => "0x#{PUPPETLABS_GPG_KEY_FINGERPRINT.downcase}",
      }

      key_versions.each do |key, value|
        context key.to_s do
          it 'works' do
            pp = <<-EOS
              #{typename} { 'puppetlabs':
                name    => '#{value}',
                ensure  => 'present',
                content => '#{fedora[:content]}',
              }
            EOS

            puts 'Add'
            execute_manifest(pp, trace: true, catch_failures: true)
            puts 'Check 1'
            check_key(fedora[:short])
            puts 'Ensure'
            execute_manifest(pp, trace: true, catch_changes: true)
            puts 'Check 2'
            check_key(fedora[:short])
          end
        end
      end

      context 'invalid length key id' do
        it 'fails' do
          pp = <<-EOS
        #{typename} { 'puppetlabs':
          id => '8280EF8D349F',
        }
        EOS

          apply_manifest(pp, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{Valid values match})
          end
        end
      end
    end

    describe 'ensure =>' do
      context 'absent' do
        it 'is removed' do
          pp = <<-EOS
        #{typename} { 'centos':
          id     => '#{CENTOS_GPG_KEY_LONG_ID}',
          ensure => 'absent',
        }
        EOS

          # Install the key first (retry because key pool may timeout)
          retry_on_error_matching(MAX_TIMEOUT_RETRY, TIMEOUT_RETRY_WAIT, TIMEOUT_ERROR_MATCHER) do
            shell_ex("apt-key adv --keyserver hkps.pool.sks-keyservers.net \
                --recv-keys #{CENTOS_GPG_KEY_FINGERPRINT}")
          end
          shell_ex(CENTOS_KEY_CHECK_COMMAND)

          # Time to remove it using Puppet
          apply_manifest(pp, catch_failures: true)
          apply_manifest(pp, catch_changes: true)

          shell_ex(CENTOS_KEY_CHECK_COMMAND,
                   acceptable_exit_codes: [1])

          # Re-Install the key (retry because key pool may timeout)
          retry_on_error_matching(MAX_TIMEOUT_RETRY, TIMEOUT_RETRY_WAIT, TIMEOUT_ERROR_MATCHER) do
            shell_ex("apt-key adv --keyserver hkps.pool.sks-keyservers.net \
                  --recv-keys #{CENTOS_GPG_KEY_FINGERPRINT}")
          end
        end
      end

      context 'absent, added with long key' do
        it 'is removed' do
          pp = <<-EOS
        #{typename} { 'puppetlabs':
          id     => '#{PUPPETLABS_GPG_KEY_LONG_ID}',
          ensure => 'absent',
        }
        EOS

          # Install the key first (retry because key pool may timeout)
          retry_on_error_matching(MAX_TIMEOUT_RETRY, TIMEOUT_RETRY_WAIT, TIMEOUT_ERROR_MATCHER) do
            shell_ex("apt-key adv --keyserver hkps.pool.sks-keyservers.net \
                  --recv-keys #{PUPPETLABS_GPG_KEY_LONG_ID}")
          end

          shell_ex(PUPPETLABS_KEY_CHECK_COMMAND)

          # Time to remove it using Puppet
          apply_manifest(pp, catch_failures: true)
          apply_manifest(pp, catch_changes: true)

          shell_ex(PUPPETLABS_KEY_CHECK_COMMAND,
                   acceptable_exit_codes: [1])
        end
      end
    end

    describe 'content =>' do
      context 'puppetlabs gpg key' do
        it 'works' do
          pp = <<-EOS
          #{typename} { 'puppetlabs':
            id      => '#{PUPPETLABS_GPG_KEY_FINGERPRINT}',
            ensure  => 'present',
            content => "#{my_fixture_read('puppetlabs_key.gpg')}",
          }
        EOS

          # Apply the manifest (Retry if timeout error is received from key pool)
          retry_on_error_matching(MAX_TIMEOUT_RETRY, TIMEOUT_RETRY_WAIT, TIMEOUT_ERROR_MATCHER) do
            apply_manifest(pp, catch_failures: true)
          end

          apply_manifest(pp, catch_changes: true)
          shell_ex(PUPPETLABS_KEY_CHECK_COMMAND)
        end
      end

      context 'multiple keys' do
        it 'runs without errors' do
          pp = <<-EOS
          #{typename} { 'puppetlabs':
            id      => '#{PUPPETLABS_GPG_KEY_FINGERPRINT}',
            ensure  => 'present',
            content => "#{my_fixture_read('puppetlabs_multiple.gpg')}",
          }
        EOS

          apply_manifest(pp, catch_failures: true)
          apply_manifest(pp, catch_changes: true)
          shell_ex(PUPPETLABS_KEY_CHECK_COMMAND)
        end
      end

      context 'bogus key' do
        it 'fails' do
          pp = <<-EOS
        #{typename} { 'puppetlabs':
          id      => '#{PUPPETLABS_GPG_KEY_LONG_ID}',
          ensure  => 'present',
          content => 'For posterity: such content, much bogus, wow',
        }
        EOS

          apply_manifest(pp, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{no valid OpenPGP data found})
          end
        end
      end
    end

    describe 'server =>' do
      context 'hkps.pool.sks-keyservers.net' do
        it 'works' do
          pp = <<-EOS
        #{typename} { 'puppetlabs':
          id     => '#{PUPPETLABS_GPG_KEY_LONG_ID}',
          ensure => 'present',
          server => 'hkps.pool.sks-keyservers.net',
        }
        EOS

          # Apply the manifest (Retry if timeout error is received from key pool)
          retry_on_error_matching(MAX_TIMEOUT_RETRY, TIMEOUT_RETRY_WAIT, TIMEOUT_ERROR_MATCHER) do
            apply_manifest(pp, catch_failures: true)
          end

          apply_manifest(pp, catch_changes: true)
          shell_ex(PUPPETLABS_KEY_CHECK_COMMAND)
        end
      end

      context 'hkp://hkps.pool.sks-keyservers.net:80' do
        it 'works' do
          pp = <<-EOS
        #{typename} { 'puppetlabs':
          id     => '#{PUPPETLABS_GPG_KEY_FINGERPRINT}',
          ensure => 'present',
          server => 'hkp://hkps.pool.sks-keyservers.net:80',
        }
        EOS

          retry_on_error_matching(MAX_TIMEOUT_RETRY, TIMEOUT_RETRY_WAIT, TIMEOUT_ERROR_MATCHER) do
            apply_manifest(pp, catch_failures: true)
          end

          apply_manifest(pp, catch_changes: true)
          shell_ex(PUPPETLABS_KEY_CHECK_COMMAND)
        end
      end

      context 'nonexistant.key.server' do
        it 'fails' do
          pp = <<-EOS
        #{typename} { 'puppetlabs':
          id     => '#{PUPPETLABS_GPG_KEY_LONG_ID}',
          ensure => 'present',
          server => 'nonexistant.key.server',
        }
        EOS

          apply_manifest(pp, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{(Host not found|Couldn't resolve host)})
          end
        end
      end

      context 'key server start with dot' do
        it 'fails' do
          pp = <<-EOS
        #{typename} { 'puppetlabs':
          id     => '#{PUPPETLABS_GPG_KEY_LONG_ID}',
          ensure => 'present',
          server => '.pgp.key.server',
        }
        EOS

          apply_manifest(pp, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{Invalid value \".pgp.key.server\"})
          end
        end
      end
    end

    describe 'source =>' do
      context 'http://' do
        it 'works' do
          pp = <<-EOS
        #{typename} { 'puppetlabs':
          id     => '#{PUPPETLABS_GPG_KEY_LONG_ID}',
          ensure => 'present',
          source => 'http://#{PUPPETLABS_APT_URL}/#{PUPPETLABS_GPG_KEY_FILE}',
        }
        EOS

          apply_manifest(pp, catch_failures: true)
          apply_manifest(pp, catch_changes: true)
          shell_ex(PUPPETLABS_KEY_CHECK_COMMAND)
        end

        it 'works with userinfo' do
          pp = <<-EOS
        #{typename} { 'puppetlabs':
          id     => '#{PUPPETLABS_GPG_KEY_LONG_ID}',
          ensure => 'present',
          source => 'http://dummyuser:dummypassword@#{PUPPETLABS_APT_URL}/#{PUPPETLABS_GPG_KEY_FILE}',
        }
        EOS

          apply_manifest(pp, catch_failures: true)
          apply_manifest(pp, catch_changes: true)
          shell_ex(PUPPETLABS_KEY_CHECK_COMMAND)
        end

        it 'fails with a 404' do
          pp = <<-EOS
        #{typename} { 'puppetlabs':
          id     => '#{PUPPETLABS_GPG_KEY_LONG_ID}',
          ensure => 'present',
          source => 'http://#{PUPPETLABS_APT_URL}/herpderp.gpg',
        }
        EOS

          apply_manifest(pp, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{404 Not Found})
          end
        end

        it 'fails with a socket error' do
          pp = <<-EOS
        #{typename} { 'puppetlabs':
          id     => '#{PUPPETLABS_GPG_KEY_LONG_ID}',
          ensure => 'present',
          source => 'http://apt.puppetlabss.com/herpderp.gpg',
        }
        EOS

          apply_manifest(pp, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{could not resolve})
          end
        end
      end

      context 'ftp://' do
        before(:each) do
          shell_ex("apt-key del #{CENTOS_GPG_KEY_LONG_ID}",
                   acceptable_exit_codes: [0, 1, 2])
        end

        it 'works' do
          pp = <<-EOS
        #{typename} { 'CentOS 6':
          id     => '#{CENTOS_GPG_KEY_LONG_ID}',
          ensure => 'present',
          source => 'ftp://#{CENTOS_REPO_URL}/#{CENTOS_GPG_KEY_FILE}',
        }
        EOS

          apply_manifest(pp, catch_failures: true)
          apply_manifest(pp, catch_changes: true)
          shell_ex(CENTOS_KEY_CHECK_COMMAND)
        end

        it 'fails with a 550' do
          pp = <<-EOS
        #{typename} { 'CentOS 6':
          id     => '#{SHOULD_NEVER_EXIST_ID}',
          ensure => 'present',
          source => 'ftp://#{CENTOS_REPO_URL}/herpderp.gpg',
        }
        EOS

          apply_manifest(pp, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{550 Failed to open})
          end
        end

        it 'fails with a socket error' do
          pp = <<-EOS
        #{typename} { 'puppetlabs':
          id     => '#{PUPPETLABS_GPG_KEY_LONG_ID}',
          ensure => 'present',
          source => 'ftp://apt.puppetlabss.com/herpderp.gpg',
        }
        EOS

          apply_manifest(pp, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{could not resolve})
          end
        end
      end

      context 'https://' do
        it 'works' do
          pp = <<-EOS
        #{typename} { 'puppetlabs':
          id     => '#{PUPPETLABS_GPG_KEY_LONG_ID}',
          ensure => 'present',
          source => 'https://#{PUPPETLABS_APT_URL}/#{PUPPETLABS_GPG_KEY_FILE}',
        }
        EOS

          apply_manifest(pp, catch_failures: true)
          apply_manifest(pp, catch_changes: true)
          shell_ex(PUPPETLABS_KEY_CHECK_COMMAND)
        end

        it 'works with userinfo' do
          pp = <<-EOS
        #{typename} { 'puppetlabs':
          id     => '#{PUPPETLABS_GPG_KEY_LONG_ID}',
          ensure => 'present',
          source => 'https://dummyuser:dummypassword@#{PUPPETLABS_APT_URL}/#{PUPPETLABS_GPG_KEY_FILE}',
        }
        EOS

          apply_manifest(pp, catch_failures: true)
          apply_manifest(pp, catch_changes: true)
          shell_ex(PUPPETLABS_KEY_CHECK_COMMAND)
        end

        it 'fails with a 404' do
          pp = <<-EOS
        #{typename} { 'puppetlabs':
          id     => '#{SHOULD_NEVER_EXIST_ID}',
          ensure => 'present',
          source => 'https://#{PUPPETLABS_APT_URL}/herpderp.gpg',
        }
        EOS

          apply_manifest(pp, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{404 Not Found})
          end
        end

        it 'fails with a socket error' do
          pp = <<-EOS
        #{typename} { 'puppetlabs':
          id     => '#{SHOULD_NEVER_EXIST_ID}',
          ensure => 'present',
          source => 'https://apt.puppetlabss.com/herpderp.gpg',
        }
        EOS

          apply_manifest(pp, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{could not resolve})
          end
        end
      end

      context '/path/that/exists' do
        before(:each) do
          shell("curl -o /tmp/puppetlabs-pubkey.gpg \
                http://#{PUPPETLABS_APT_URL}/#{PUPPETLABS_GPG_KEY_FILE}")
        end

        after(:each) do
          shell('rm /tmp/puppetlabs-pubkey.gpg')
        end

        it 'works' do
          pp = <<-EOS
        #{typename} { 'puppetlabs':
          id     => 'EF8D349F',
          ensure => 'present',
          source => '/tmp/puppetlabs-pubkey.gpg',
        }
        EOS

          apply_manifest(pp, catch_failures: true)
          apply_manifest(pp, catch_changes: true)
          shell(PUPPETLABS_KEY_CHECK_COMMAND)
        end
      end

      context '/path/that/does/not/exist' do
        it 'fails' do
          pp = <<-EOS
        #{typename} { 'puppetlabs':
          id     => '#{PUPPETLABS_GPG_KEY_LONG_ID}',
          ensure => 'present',
          source => '/tmp/totally_bogus.file',
        }
        EOS

          apply_manifest(pp, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{does not exist})
          end
        end
      end

      context '/path/that/exists/with/bogus/content' do
        before(:each) do
          shell('echo "here be dragons" > /tmp/fake-key.gpg')
        end

        after(:each) do
          shell('rm /tmp/fake-key.gpg')
        end
        it 'fails' do
          pp = <<-EOS
        #{typename} { 'puppetlabs':
          id     => '#{PUPPETLABS_GPG_KEY_LONG_ID}',
          ensure => 'present',
          source => '/tmp/fake-key.gpg',
        }
        EOS

          apply_manifest(pp, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{no valid OpenPGP data found})
          end
        end
      end
    end

    describe 'options =>' do
      context 'debug' do
        it 'works' do
          pp = <<-EOS
        #{typename} { 'puppetlabs':
          id      => '#{PUPPETLABS_GPG_KEY_LONG_ID}',
          ensure  => 'present',
          options => 'debug',
        }
        EOS

          apply_manifest(pp, catch_failures: true)
          apply_manifest(pp, catch_changes: true)
          shell(PUPPETLABS_KEY_CHECK_COMMAND)
        end
      end
    end

    describe 'fingerprint validation against source/content' do
      context 'fingerprint in id matches fingerprint from remote key' do
        it 'works' do
          pp = <<-EOS
        #{typename} { 'puppetlabs':
          id      => '#{PUPPETLABS_GPG_KEY_FINGERPRINT}',
          ensure  => 'present',
          source  => 'https://#{PUPPETLABS_APT_URL}/#{PUPPETLABS_GPG_KEY_FILE}',
        }
        EOS

          apply_manifest(pp, catch_failures: true)
          apply_manifest(pp, catch_changes: true)
        end
      end

      context 'fingerprint in id does NOT match fingerprint from remote key' do
        it 'works' do
          pp = <<-EOS
         { 'puppetlabs':
          id      => '6F6B15509CF8E59E6E469F327F438280EF8D9999',
          ensure  => 'present',
          source  => 'https://#{PUPPETLABS_APT_URL}/#{PUPPETLABS_GPG_KEY_FILE}',
        }
        EOS

          apply_manifest(pp, expect_failures: true) do |r|
            expect(r.stderr).to match(%r{do not match})
          end
        end
      end
    end
  end
end
