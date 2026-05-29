# frozen_string_literal: true
# Seeded bugs: command injection. Safe counterparts as negative controls.

class CmdRunner
  def vulnerable_backtick(name)
    `convert #{name} out.png`           # BUG: cmd_injection (backtick interp)
  end

  def vulnerable_system(path)
    system("tar xf #{path}")            # BUG: cmd_injection (system interp)
  end

  def vulnerable_popen(host)
    IO.popen("ping -c1 #{host}")        # BUG: cmd_injection (IO.popen interp)
  end

  def safe_system(path)
    system("tar", "xf", path)           # SAFE: argv array, no shell
  end
end
