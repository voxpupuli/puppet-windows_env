class windows_env {
  ### SHOULD FAIL ###

  # ensure => present, but no value
  windows_env { 'SHOULD_FAIL1': }

  # ensure => absent, mergemode => insert, but no value
  windows_env { 'SHOULD_FAIL2':
    mergemode => insert,
    ensure    => absent,
  }

  # nonexistent user
  windows_env { 'SHOULD_FAIL3':
    value => 'hello',
    user  => 'jibberishuserwhoshouldnotexist',
  }

  ### SHOULD PASS ###

  # Should insert 'C:\foo' at end of PATH
  windows_env { 'PATH=C:\foo':
    mergemode => append,
  }

  # Should insert 'C:\hello;C:\byebye' at the front of PATH
  windows_env { 'PATH':
    mergemode => prepend,
    value     => ['C:\hello', 'C:\byebye'],
  }

  # Should insert 'value' into 'PATH'
  windows_env { 'Puppet':
    variable  => 'PATH',
    value     => 'C:\Program Files (x86)\Puppet Labs\Puppet\bin',
    mergemode => insert,
  }

  # Should create an environment variable 'JIMMY' with value
  # 'ah-ja'
  windows_env { 'JIMMY=ah-ja':
    mergemode => clobber,
  }

  # Should create environment variable 'TESTER2' with value
  # "hello:there"
  windows_env {'TESTER':
    variable  => 'TESTER2',
    mergemode => clobber,
    value     => ['hello', 'there'],
    separator => ':',
  }

  # Should create an environment variable 'JAVA_HOME' of type REG_EXPAND_SZ
  windows_env { 'JAVA_HOME=%ProgramFiles%\Java\jdk1.6.0_02':
    mergemode => clobber,
    type      => REG_EXPAND_SZ,
  }

  # should create an environment variable 'VARGUY', then insert a new value and change its type
  windows_env { 'VARGUY=C:\hello': }->
  windows_env { 'VARGUY=C:\byebye':
    type => REG_EXPAND_SZ,
  }

  # Should create a variable 'DELETME', and then delete it. 
  windows_env { 'DELETEME1':
    mergemode => clobber,
    ensure    => present,
    value     => '',
    variable  => 'DELETEME',
  }->
  windows_env { 'DELETEME2':
    mergemode => clobber,
    ensure    => absent,
    variable  => 'DELETEME',
  }

  # Should remove 'C:\path' from PATH. 
  windows_env { 'DELETEME3':
    variable => 'PATH',
    ensure   => absent,
    value    => 'C:\path',
  }

  # Should add 'C:\somecode\bin' to Administrator account's PATH. 
  windows_env { 'PATH=C:\somecode\bin':
    user => 'Administrator',
  }

  # Should remove 'C:\badcode\bin' from Administrator account's PATH. 
  windows_env { 'PATH=C:\badcode\bin':
    user   => 'Administrator',
    ensure => absent,
  }

  # Should set environment variable 'X' in the registry *and* in the ruby
  # process' environment, such that the exec sees the new value of X.
  windows_env { "X=12":
    mergemode       => clobber,
    update_ruby_env => true,
  }->
  exec { 'cmd.exe /c echo %X%':
    logoutput => true,
    path      => $::path,
  }
}

