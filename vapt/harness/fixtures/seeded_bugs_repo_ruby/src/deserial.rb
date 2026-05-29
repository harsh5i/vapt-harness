# frozen_string_literal: true
# Seeded bugs: unsafe deserialization.

class Deserial
  def vulnerable_marshal(blob)
    Marshal.load(blob)                  # BUG: unsafe_deserialization
  end

  def vulnerable_yaml(io)
    YAML.load(io.read)                  # BUG: unsafe_deserialization (not safe_load)
  end

  def safe_yaml(io)
    YAML.safe_load(io.read)             # SAFE: safe_load
  end
end
