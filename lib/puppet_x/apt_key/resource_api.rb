require 'pathname'

module Puppet::SimpleResource
  class TypeShim
    attr_reader :values

    def initialize(title, resource_hash)
      # internalize and protect - needs to go deeper
      @values        = resource_hash.dup
      # "name" is a privileged key
      @values[:name] = title
      @values.freeze
    end

    def to_resource
      ResourceShim.new(@values)
    end

    def name
      values[:name]
    end
  end

  class ResourceShim
    attr_reader :values

    def initialize(resource_hash)
      @values = resource_hash.dup.freeze # whatevs
    end

    def title
      values[:name]
    end

    def prune_parameters(*args)
      # puts "not pruning #{args.inspect}" if args.length > 0
      self
    end

    def to_manifest
      (["apt_key { #{values[:name].inspect}: "] + values.keys.select { |k| k != :name }.collect { |k| "  #{k} => #{values[k].inspect}," } + ['}']).join("\n")
    end
  end
end

def register_type(definition)
  Puppet::Type.newtype(definition[:name].to_sym) do
    @docs = definition[:docs]
    has_namevar = false
    namevar_name = nil

    def initialize(attributes)
      $stderr.puts "A: #{attributes.inspect}"
      attributes = attributes.to_hash if attributes.is_a? Puppet::Resource
      $stderr.puts "B: #{attributes.inspect}"
      attributes = self.class.canonicalize([attributes])[0]
      $stderr.puts "C: #{attributes.inspect}"
      super(attributes)
    end

    definition[:attributes].each do |name, options|
      # puts "#{name}: #{options.inspect}"

      # TODO: using newparam everywhere would suppress change reporting
      #       that would allow more fine-grained reporting through logger,
      #       but require more invest in hooking up the infrastructure to emulate existing data
      param_or_property = if options[:read_only] || options[:namevar]
                            :newparam
                          else
                            :newproperty
                          end
      send(param_or_property, name.to_sym) do
        unless options[:type]
          fail("#{definition[:name]}.#{name} has no type")
        end

        if options[:docs]
          desc "#{options[:docs]} (a #{options[:type]}"
        else
          warn("#{definition[:name]}.#{name} has no docs")
        end

        if options[:namevar]
          puts 'setting namevar'
          isnamevar
          has_namevar = true
          namevar_name = name
        end

        # read-only values do not need type checking, but can have default values
        if not options[:read_only]
          # TODO: this should use Pops infrastructure to avoid hardcoding stuff, and enhance type fidelity
          # validate do |v|
          #   type = Puppet::Pops::Types::TypeParser.singleton.parse(options[:type]).normalize
          #   if type.instance?(v)
          #     return true
          #   else
          #     inferred_type = Puppet::Pops::Types::TypeCalculator.infer_set(value)
          #     error_msg = Puppet::Pops::Types::TypeMismatchDescriber.new.describe_mismatch("#{DEFINITION[:name]}.#{name}", type, inferred_type)
          #     raise Puppet::ResourceError, error_msg
          #   end
          # end

          if options.has_key? :default
            defaultto options[:default]
          end

          case options[:type]
            when 'String'
              # require any string value
              newvalue // do
              end
            when 'Boolean'
              ['true', 'false', :true, :false, true, false].each do |v|
                newvalue v do
                end
              end

              munge do |v|
                case v
                  when 'true', :true
                    true
                  when 'false', :false
                    false
                  else
                    v
                end
              end
            when 'Integer'
              newvalue /^\d+$/ do
              end
              munge do |v|
                Puppet::Pops::Utils.to_n(v)
              end
            when 'Float', 'Numeric'
              newvalue Puppet::Pops::Patterns::NUMERIC do
              end
              munge do |v|
                Puppet::Pops::Utils.to_n(v)
              end
            when 'Enum[present, absent]'
              newvalue :absent do
              end
              newvalue :present do
              end
            when 'Variant[Pattern[/\A(0x)?[0-9a-fA-F]{8}\Z/], Pattern[/\A(0x)?[0-9a-fA-F]{16}\Z/], Pattern[/\A(0x)?[0-9a-fA-F]{40}\Z/]]'
              # the namevar needs to be a Parameter, which only has newvalue*s*
              newvalues(/\A(0x)?[0-9a-fA-F]{8}\Z/, /\A(0x)?[0-9a-fA-F]{16}\Z/, /\A(0x)?[0-9a-fA-F]{40}\Z/)
            when 'Optional[String]'
              newvalue :undef do
              end
              newvalue // do
              end
            when 'Variant[Stdlib::Absolutepath, Pattern[/\A(https?|ftp):\/\//]]'
              # TODO: this is wrong, but matches original implementation
              [/^\//, /\A(https?|ftp):\/\//].each do |v|
                newvalue v do
                end
              end
            when /^(Enum|Optional|Variant)/
              fail("#{$1} is not currently supported")
          end
        end
      end
    end

    define_singleton_method(:instances) do
      puts 'instances'
      # klass = Puppet::Type.type(:api)
      # force autoloading of the provider
      autoloaded_provider = provider(name)
      get.collect do |resource_hash|
        Puppet::SimpleResource::TypeShim.new(resource_hash[namevar_name], resource_hash)
      end
    end

    define_method(:retrieve) do
      puts 'retrieve'
      result        = Puppet::Resource.new(self.class, title)
      current_state = self.class.get.find { |h| h[namevar_name] == title }

      if current_state
        current_state.each do |k, v|
          result[k]=v
        end
      else
        result[:ensure] = :absent
      end

      @rapi_current_state = current_state
      result
    end

    def flush
      puts 'flush'
      # binding.pry
      target_state = self.class.canonicalize([Hash[@parameters.collect { |k, v| [k, v.value] }]])
      if @rapi_current_state != target_state
        self.class.set({title => @rapi_current_state}, {title => target_state}, false)
      else
        puts 'no changes'
      end
    end

    def self.commands(*args)
      args.each do |command_group|
        command_group.each do |command_name, command|
          puts "registering command: #{command_name}, using #{command}"
          define_singleton_method(command_name) do |*args|
            puts "spawn([#{command.to_s}, #{command.to_s}], #{args.inspect})"
            # TODO: capture output to debug stream
            p = Process.spawn([command, command], *args)
            Process.wait(p)
            unless $?.exitstatus == 0
              raise Puppet::ResourceError, "#{command} failed with exit code #{$?.exitstatus}"
            end
          end

          define_singleton_method("#{command_name}_lines") do |*args|
            puts "capture3([#{command.to_s}, #{command.to_s}], #{args.inspect})"
            stdin_str, stderr_str, status = Open3.capture3([command, command], *args)
            unless status.exitstatus == 0
              raise Puppet::ResourceError, "#{command} failed with exit code #{$?.exitstatus}"
            end
            stdin_str.split("\n")
          end
        end
      end
    end
  end
end

def register_provider(typename, &block)
  type = Puppet::Type.type(typename.to_sym)
  type.instance_eval &block
  # require'pry';binding.pry
end
