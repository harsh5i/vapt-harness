# frozen_string_literal: true
# Seeded bugs: unsafe reflection / eval.

class Reflect
  def vulnerable_constantize(klass)
    params[:type].constantize.new          # BUG: unsafe_reflection (constantize on input)
  end

  def vulnerable_send(obj)
    obj.send(params[:method])              # BUG: unsafe_reflection (dynamic send)
  end

  def vulnerable_eval(expr)
    eval(expr)                             # BUG: unsafe_reflection (eval)
  end

  def safe_send(obj)
    obj.send(:to_s)                        # SAFE: literal symbol
  end

  def safe_constantize
    "User".constantize                     # SAFE: literal receiver
  end
end
