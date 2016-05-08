# Depending on puppet version, this feature may or may not include the libraries needed, but
# if some of them are present, the others should be too. This check prevents errors from 
# non Windows nodes that have had this module pluginsynced to them. 
if Puppet.features.microsoft_windows?
  require 'puppet/util/windows/error'
  require 'puppet/util/windows/security'
  require 'win32/registry' 
  module Win32
    class Registry
      KEY_WOW64_64KEY = 0x0100 unless defined?(KEY_WOW64_64KEY)
    end
  end
end

require 'puppet/util/feature'

Puppet.features.add(:windows_env, :libs => ['ffi'])

if Puppet.version < '3.4.0'
  # This is the best pre-3.4.0 way to do unconditional cleanup for a provider.
  # see https://groups.google.com/forum/#!topic/puppet-dev/Iqs5jEGfu_0
  module Puppet
    class Transaction
      # The alias name (evaluate_orig_windows_env) should be unique to make
      # sure that if somebody else does this monkey patch, they don't choose
      # the same name and cause ruby to blow up.
      alias_method :evaluate_orig_windows_env, :evaluate
      def evaluate
        evaluate_orig_windows_env
        begin
          Puppet::Type::Windows_env::ProviderWindows_env.post_resource_eval
        rescue => detail
          Puppet.log_exception(detail, "post_resource_eval failed for provider windows_env")
        end
      end
    end
  end
end

Puppet::Type.type(:windows_env).provide(:windows_env) do
  desc "Manage Windows environment variables"

  confine :feature => :windows_env
  confine :osfamily => :windows
  defaultfor :osfamily => :windows

  # The 'windows_env' feature includes FFI.  Here we need to be able to fully
  # load the provider even if FFI is absent so that the catalog can continue
  # (and hopefully install FFI).
  if Puppet.features.windows_env? && Puppet.features.microsoft_windows?
    module self::WinAPI
      extend FFI::Library

      ffi_convention :stdcall

      ffi_lib :User32
      attach_function :SendMessageTimeout, :SendMessageTimeoutA, [:uintptr_t, :uint, :pointer, :pointer, :uint, :uint, :pointer], :pointer

      ffi_lib :Advapi32
      attach_function :RegLoadKey, :RegLoadKeyA, [:uintptr_t, :pointer, :pointer], :long
      attach_function :RegUnLoadKey, :RegUnLoadKeyA, [:uintptr_t, :pointer], :long

      # Ruby < 1.9 doesn't know about encoding.
      if defined?(::Encoding) && defined?(Puppet::Util::Windows::String)
        # Workaround for https://bugs.ruby-lang.org/issues/10820 .
        attach_function :RegDeleteValue, :RegDeleteValueW, [:uintptr_t, :buffer_in], :long

        # Borrowed from Puppet core. Duplicated for old version compatibilty.
        def self.from_string_to_wide_string(str, &block)
          # TODO:
          # Puppet::Util::Windows::String is new in Puppet 3.4.3.
          str = Puppet::Util::Windows::String.wide_string(str)
          FFI::MemoryPointer.new(:byte, str.bytesize) do |ptr|
            # uchar here is synonymous with byte
            ptr.put_array_of_uchar(0, str.bytes.to_a)
            yield ptr
          end
          # ptr has already had free called, so nothing to return
          nil
        end

        def self.delete_value(key, name)
          result = nil
          from_string_to_wide_string(name) do |name_ptr|
            result = RegDeleteValue(key.hkey, name_ptr)
          end
          result
        end
      else
        def self.delete_value(key, name)
          key.delete_value(name)
        end
      end
    end
  end

  # Instances can load hives with #load_user_hive . The class takes care of
  # unloading all hives. 
  @loaded_hives = []
  class << self
    attr_reader :loaded_hives
  end

  def self.post_resource_eval
    Puppet::Util::Windows::Security.with_privilege(Puppet::Util::Windows::Security::SE_RESTORE_NAME) do
      @loaded_hives.each do |hash| 
        user_sid = hash[:user_sid]
        username = hash[:username]
        debug "Unloading NTUSER.DAT for '#{username}'"
        result = self::WinAPI.RegUnLoadKey(Win32::Registry::HKEY_USERS.hkey, user_sid)
      end
    end
  end

  def exists?
    @value = get_current_reg_val()

    # Assume that if the user says 'ensure => absent', they want the value to
    # be removed regardless of its position, i.e. use the 'insert' behavior
    # when removing in 'prepend' and 'append' modes. Otherwise, if the value
    # were in the variable but not at the beginning (prepend) or end (append),
    # it would not be removed. 
    if @resource[:ensure] == :absent && [:append, :prepend].include?(@resource[:mergemode])
      @resource[:mergemode] = :insert
    end

    # We might be running in a stale environment and want to update ruby's
    # environment to match what's in the registry. While we could return a
    # value from #exists? in this case that forces all the other code to run,
    # this would probably not be what the user wants (since it'll trigger
    # subscribed resources and such even when the registry was already
    # correct). So instead, just update the environment quietly.
    if @resource[:update_ruby_env] == :true
      exists_current_env = exists_helper(ENV[@resource[:variable]])
      if (@resource[:ensure] == :present && ! exists_current_env) ||
         (@resource[:ensure] == :absent && exists_current_env)
        # TODO: utf-16le stuff eith ENV ???
        debug "updating ruby envrionment to match puppet defined value"
        ENV[@resource[:variable]] = get_desired_value(ENV[@resource[:variable]])
      end
    end

    # TODO remove
    debug "@value = '#{@value}'"
    exists = exists_helper(@value)
    debug "Returning exists == #{exists}"
    exists
  end

  def create
    debug "Creating or inserting value into environment variable '#{@resource[:variable]}'"

    desired_value = get_desired_value(@value)
    # TODO: remove
    debug "#create: desired_value == '#{desired_value}'"

    # Creating a new key or updating an old?
    if @value.nil?
      @reg_type = Win32::Registry::REG_SZ unless @reg_type
      begin
        @reg_hive.create(@reg_path, Win32::Registry::KEY_ALL_ACCESS | Win32::Registry::KEY_WOW64_64KEY) do |key| 
          key[@resource[:variable], @reg_type] = desired_value
        end
      rescue Win32::Registry::Error => error
        reg_fail('creating', error)
      end
    else
      @value = desired_value
      key_write
    end

    broadcast_changes
  end

  def destroy
    debug "Removing value from environment variable '#{@resource[:variable]}', or removing variable itself"

    @value = get_desired_value(@value)
    # TODO: remove
    debug "@value = get_desried_value(@value) == '#{@value.to_s}'"
    debug "@value.class == #{@value.class}"
    if @value.nil?
      # TODO: remove
      debug "@value nil, deleting variable"
      key_write { |key| self.class::WinAPI.delete_value(key, @resource[:variable]) }
    else
      key_write
    end

    broadcast_changes
  end

  def type
    # QueryValue returns '[type, value]'
     current_type = @reg_hive.open(@reg_path) { |key| Win32::Registry::API.QueryValue(key.hkey, @resource[:variable]) }[0]
     @reg_types.invert[current_type]
  end

  def type=(newtype)
    newtype = @reg_types[newtype]
    key_write { |key| key[@resource[:variable], newtype] = @value }
    broadcast_changes
  end

  private

  # name_to_sid moved from 'security' to 'sid' in Puppet 3.7.
  # 'puppet/util/windows/sid' is not guaranteed to exist on older 3.x Puppets.
  use_util_windows_sid = false
  begin
    require 'puppet/util/windows/sid'
    if Puppet::Util::Windows::SID.respond_to?(:name_to_sid)
      use_util_windows_sid = true
    end
  rescue LoadError
  end
  if use_util_windows_sid
    def name_to_sid(name)
      Puppet::Util::Windows::SID.name_to_sid(name)
    end
  else
    def name_to_sid(name)
      Puppet::Util::Windows::Security.name_to_sid(name)
    end
  end

  def reg_fail(action, error)
    self.fail "#{action} '#{@reg_hive.name}:\\#{@reg_path}\\#{@resource[:variable]}' returned error #{error.code}: #{error.message}"
  end

  def remove_value(current)
    current.delete_if { |x| @resource[:value].find { |y| y.casecmp(x) == 0 } }
    current
  end

  # Determine if #exists? should return true. This is abstracted out because we need to
  # check two kinds of existence: existence in the registry and existence in the current
  # ruby process' environment.
  # current_value may be nil if the variable doesn't exist.
  def exists_helper(current_value)
    # No variable; definitely doesn't exist.
    return false if current_value.nil?

    current_value = current_value.split(@resource[:separator])

    case @resource[:mergemode]
    when :clobber
      # TODO: remove
      debug "current_value = '#{current_value}' @resource[:value] == '#{@resource[:value]}'"
      current_value == @resource[:value]
    when :insert
      # FIXME: this is a weird way to do this
      # verify all elements are present and they appear in the correct order
      indexes = @resource[:value].map { |x| current_value.find_index { |y| x.casecmp(y) == 0 } }
      if indexes.count == 1
        indexes == [nil] ? false : true
      else
        indexes.each_cons(2).all? { |a, b| a && b && a < b }
      end
    when :append
      current_value.map { |x| x.downcase }[(-1 * @resource[:value].count)..-1] == @resource[:value].map { |x| x.downcase }
    when :prepend
      current_value.map { |x| x.downcase }[0..(@resource[:value].count - 1)] == @resource[:value].map { |x| x.downcase }
    end
  end

  # Get the current value of the environment variable in the registry. Return
  # nil if the variable is not present.
  def get_current_reg_val
    # For testing registry open result
    _ERROR_FILE_NOT_FOUND = 2

    if @resource[:user]
      @reg_hive = Win32::Registry::HKEY_USERS
      user_sid = name_to_sid(@resource[:user])
      user_sid or self.fail "Username '#{@resource[:user]}' could not be converted to a valid SID"
      @reg_path = "#{user_sid}\\Environment"

      begin
        @reg_hive.open(@reg_path) {}
      rescue Win32::Registry::Error => error
        if error.code == _ERROR_FILE_NOT_FOUND
          load_user_hive(user_sid)
        else
          reg_fail("Can't access Environment for user '#{@resource[:user]}'. Opening", error)
        end
      end
    else
      @reg_hive = Win32::Registry::HKEY_LOCAL_MACHINE
      @reg_path = 'System\CurrentControlSet\Control\Session Manager\Environment'
    end

    @reg_types = { :REG_SZ => Win32::Registry::REG_SZ, :REG_EXPAND_SZ => Win32::Registry::REG_EXPAND_SZ }
    @reg_type = @reg_types[@resource[:type]]

    current_value = nil
    begin
      # key.read returns '[type, data]' and must be used instead of [] because [] expands %variables%. 
      @reg_hive.open(@reg_path) { |key| current_value = key.read(@resource[:variable])[1] } 
    rescue Win32::Registry::Error => error
      if error.code == _ERROR_FILE_NOT_FOUND
        debug "Environment variable #{@resource[:variable]} not found"
      else
        reg_fail('reading', error)
      end
    end

    current_value
  end

  # Get the desired value of the environment variable. If
  # the variable is to be deleted, return nil.
  def get_desired_value(current_value)
    current_value = current_value.nil? ? [] : current_value.split(@resource[:separator])

    if @resource[:ensure] == :present
      case @resource[:mergemode]
      when :clobber
        val = [@resource[:value]]
      # the position at which the new value will be inserted when using insert is
      # arbitrary, so may as well group it with append.
      when :insert, :append
        # delete if already in the string and move to end.
        val = remove_value(current_value)
        val = val.concat(@resource[:value])
      when :prepend
        # delete if already in the string and move to front
        val = remove_value(current_value)
        val = @resource[:value].concat(val)
      end
    else
      if @resource[:mergemode] == :clobber
        val = nil
      else
        val = remove_value(current_value)
      end
    end

    val.nil? ? nil : val.join(@resource[:separator])
  end

  def key_write(&block)
    unless block_given?
      if ! [nil, :nil, :undef].include?(@resource[:type]) && self.type != @resource[:type]
        # It may be the case that #exists? returns false, but we're still not creating a
        # new registry value (e.g. when mergmode => insert). In this case, the property getters/setters
        # won't be called, so we'll go ahead and set type here manually. 
        newtype = @reg_types[@resource[:type]]
      else
        newtype = @reg_types[self.type]
      end
      block = proc { |key| key[@resource[:variable], newtype] = @value }
    end
    @reg_hive.open(@reg_path, Win32::Registry::KEY_WRITE | Win32::Registry::KEY_WOW64_64KEY, &block) 
  rescue Win32::Registry::Error => error
    reg_fail('writing', error)
  end

  # Make new variable visible without logging off and on again. This really only makes sense
  # for debugging (i.e. with 'puppet agent -t') since you can only broadcast messages to your own
  # windows, and not to those of other users. 
  # see: http://stackoverflow.com/questions/190168/persisting-an-environment-variable-through-ruby/190437#190437
  #
  # Note also that we update ruby's ENV variable (unless update_ruby_env is
  # false), so the Puppet process will know about the change right away.
  def broadcast_changes
    debug "Broadcasting changes to environment"
    _HWND_BROADCAST = 0xFFFF
    _WM_SETTINGCHANGE = 0x1A
    self.class::WinAPI.SendMessageTimeout(_HWND_BROADCAST, _WM_SETTINGCHANGE, nil, 'Environment', 2, @resource[:broadcast_timeout], nil)
  end

  # This is the best solution I found to (at least mostly) reliably locate a user's 
  # ntuser.dat: http://stackoverflow.com/questions/1059460/shgetfolderpath-for-a-specific-user
  def load_user_hive(user_sid)
    debug "Loading NTUSER.DAT for '#{@resource[:user]}'"

    home_path = nil
    begin
      Win32::Registry::HKEY_LOCAL_MACHINE.open("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\#{user_sid}") do |key|
        home_path = key['ProfileImagePath']
      end
    rescue Win32::Registry::Error => error
      self.fail "Cannot find registry hive for user '#{@resource[:user]}'"
    end

    ntuser_path = File.join(home_path, 'NTUSER.DAT')

    Puppet::Util::Windows::Security.with_privilege(Puppet::Util::Windows::Security::SE_RESTORE_NAME) do
      result = self.class::WinAPI.RegLoadKey(Win32::Registry::HKEY_USERS.hkey, user_sid, ntuser_path)
      unless result == 0
        raise Puppet::Util::Windows::Error.new("Could not load registry hive for user '#{@resource[:user]}'", result)
      end
    end

    self.class.loaded_hives << { :user_sid => user_sid, :username => @resource[:user] }
  end
end

