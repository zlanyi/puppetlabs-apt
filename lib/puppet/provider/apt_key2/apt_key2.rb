require 'net/ftp'
require 'open-uri'
require 'puppet/resource_api'
require 'tempfile'

class Puppet::Provider::AptKey2::AptKey2

  def initialize
    @apt_key_cmd = Puppet::ResourceApi::Command.new 'apt-key'
    @gpg_cmd = Puppet::ResourceApi::Command.new '/usr/bin/gpg'
  end

  def canonicalize(resources)
    resources.each do |r|
      r[:id] = if r[:id].start_with?('0x')
                 r[:id][2..-1].upcase
               else
                 r[:id].upcase
               end
    end
  end

  def get(context)
    pub_line   = nil
    fpr_line   = nil

    result = @apt_key_cmd.start_read(context, %w[adv --list-keys --with-colons --fingerprint --fixed-list-mode]) do |handle|
      handle.stdout.each_line.map { |line|
        line = line.encode('UTF-8', 'binary', invalid: :replace, undef: :replace, replace: '')
        if line.start_with?('pub')
          pub_line = line
        elsif line.start_with?('fpr')
          fpr_line = line
        end
        # puts "debug: parsing #{line}; fpr: #{fpr_line.inspect}; pub: #{pub_line.inspect}"

        next unless pub_line && fpr_line

        # puts "debug: key_line_to_hash"

        hash = key_line_to_hash(pub_line, fpr_line)

        # reset scanning
        pub_line = nil
        fpr_line = nil

        hash
      }.compact!

      result
    end
  end

  def self.key_line_to_hash(pub_line, fpr_line)
    pub_split = pub_line.split(':')
    fpr_split = fpr_line.split(':')

    # set key type based on types defined in /usr/share/doc/gnupg/DETAILS.gz
    key_type  = case pub_split[3]
                when '1'
                  :rsa
                when '17'
                  :dsa
                when '18'
                  :ecc
                when '19'
                  :ecdsa
                else
                  :unrecognized
                end

    fingerprint = fpr_split.last
    expiry      = pub_split[6].empty? ? nil : Time.at(pub_split[6].to_i)

    {
      ensure:      'present',
      id:          fingerprint,
      fingerprint: fingerprint,
      long:        fingerprint[-16..-1], # last 16 characters of fingerprint
      short:       fingerprint[-8..-1], # last 8 characters of fingerprint
      size:        pub_split[2].to_i,
      type:        key_type,
      created:     Time.at(pub_split[5].to_i),
      expiry:      expiry,
      expired:     !!(expiry && Time.now >= expiry),
    }
  end

  def set(current_state, target_state, noop = false)
    target_state.each do |title, resource|
      logger.warning(title, 'The id should be a full fingerprint (40 characters) to avoid collision attacks, see the README for details.') if title.length < 40
      if resource[:source] && resource[:content]
        logger.fail(title, 'The properties content and source are mutually exclusive')
        next
      end

      current = current_state[title]
      if current && resource[:ensure].to_s == 'absent'
        logger.deleting(title) do
          begin
            apt_key('del', resource[:short], noop: noop)
            r = execute(["#{command(:apt_key)} list | grep '/#{resource[:short]}\s'"], failonfail: false)
          end while r.exitstatus.zero?
        end
      elsif current && resource[:ensure].to_s == 'present'
        logger.warning(title, 'No updating implemented')
        # update(key, noop: noop)
      elsif !current && resource[:ensure].to_s == 'present'
        create(title, resource, noop: noop)
      end
    end
  end

  def create(title, resource, noop = false)
    logger.creating(title) do |logger|
      if resource[:source].nil? && resource[:content].nil?
        # Breaking up the command like this is needed because it blows up
        # if --recv-keys isn't the last argument.
        args = ['adv', '--keyserver', resource[:server]]
        if resource[:options]
          args.push('--keyserver-options', resource[:options])
        end
        args.push('--recv-keys', resource[:id])
        apt_key(*args, noop: noop)
      elsif resource[:content]
        temp_key_file(resource[:content], logger) do |key_file|
          apt_key('add', key_file, noop: noop)
        end
      elsif resource[:source]
        key_file = source_to_file(resource[:source])
        apt_key('add', key_file.path, noop: noop)
        # In case we really screwed up, better safe than sorry.
      else
        logger.fail("an unexpected condition occurred while trying to add the key: #{title} (content: #{resource[:content].inspect}, source: #{resource[:source].inspect})")
      end
    end
  end

  # This method writes out the specified contents to a temporary file and
  # confirms that the fingerprint from the file, matches the long key that is in the manifest
  def temp_key_file(resource, logger)
    file = Tempfile.new('apt_key')
    begin
      file.write resource[:content]
      file.close
      if name.size == 40
        if File.executable? command(:gpg)
          extracted_key = execute(["#{command(:gpg)} --with-fingerprint --with-colons #{file.path} | awk -F: '/^fpr:/ { print $10 }'"], failonfail: false)
          extracted_key = extracted_key.chomp

          unless extracted_key =~ %r{^#{name}$}
            logger.fail("The id in your manifest #{resource[:id]} and the fingerprint from content/source do not match. "\
              ' Please check there is not an error in the id or check the content/source is legitimate.')
          end
        else
          logger.warning('/usr/bin/gpg cannot be found for verification of the id.')
        end
      end
      yield file.path
    ensure
      file.close
      file.unlink
    end
  end
end
