# frozen_string_literal: true
# Seeded bugs: SSRF and template injection.

class Fetch
  def vulnerable_open_uri(url)
    URI.open(url).read                     # BUG: ssrf_open_uri
  end

  def vulnerable_net_http(host)
    Net::HTTP.get(URI("https://#{host}/api"))  # BUG: ssrf_open_uri (interp)
  end

  def vulnerable_render(snippet)
    render inline: snippet                  # BUG: template_injection
  end

  def vulnerable_erb(tmpl)
    ERB.new(tmpl).result(binding)           # BUG: template_injection
  end
end
