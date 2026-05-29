# frozen_string_literal: true
# Seeded bugs: SQL injection via string interpolation.

class Queries
  def vulnerable_where(term)
    User.where("name = '#{term}'")              # BUG: sql_injection_string_interp
  end

  def vulnerable_order(col)
    Post.order("#{col} DESC")                   # BUG: sql_injection_string_interp
  end

  def vulnerable_raw(id)
    ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE id = #{id}")  # BUG
  end

  def safe_where(term)
    User.where("name = ?", term)                # SAFE: bind parameter
  end
end
