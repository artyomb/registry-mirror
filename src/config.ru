require 'sinatra'
require 'fileutils'
require 'faraday'
require 'json'
require 'digest'

require 'stack-service-base'

StackServiceBase.rack_setup self

UPSTREAM = ENV.fetch('UPSTREAM', 'https://registry-1.docker.io')
TTL      = ENV.fetch('TTL', '3600').to_i
CACHE    = ENV.fetch('CACHE_DIR', 'cache')

FileUtils.mkdir_p(CACHE)

conn = Faraday.new(url: UPSTREAM) do |f|
  f.response :raise_error # raise on 4xx/5xx so we can passthrough status
  f.adapter Faraday.default_adapter
end

helpers do
  def cache_key
    raw = "#{request.request_method} #{request.path}?#{request.query_string}"
    Digest::SHA256.hexdigest(raw)
  end

  def body_path;   File.join(CACHE, "#{cache_key}.body");   end
  def meta_path;   File.join(CACHE, "#{cache_key}.meta");   end
  def cached?
    return false unless File.exist?(body_path) && File.exist?(meta_path)
    (Time.now - File.mtime(body_path)) < TTL
  end

  def load_meta
    JSON.parse(File.read(meta_path)) rescue {}
  end

  def save_cache(status, headers, body)
    File.write(body_path, body, mode: "wb")
    meta = { "status" => status, "headers" => { "Content-Type" => headers['content-type'] } }
    File.write(meta_path, JSON.dump(meta))
  end

  def pass_headers
    # keep it simple; add more if you need them
    h = {}
    %w[Authorization Accept Range User-Agent].each do |k|
      rk = "HTTP_#{k.tr('-', '_')}"
      h[k] = env[rk] if env[rk]
    end
    h
  end
end

# GET only; extend as needed
get '/*' do
  if cached?
    meta = load_meta
    content_type(meta.dig("headers","Content-Type") || 'application/octet-stream')
    return send_file(body_path)
  end

  begin
    resp = conn.get(request.path, params, pass_headers)
    save_cache(resp.status, resp.headers, resp.body) if resp.status == 200
    status resp.status
    content_type resp.headers['content-type'] if resp.headers['content-type']
    body resp.body
  rescue Faraday::ClientError => e
    if e.response
      status e.response[:status] || 502
      headers e.response[:headers] || {}
      body e.response[:body] || e.message
    else
      status 502
      body e.message
    end
  end
end

run Sinatra::Application
