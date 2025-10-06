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

helpers do
  def conn
    @conn ||= Faraday.new(url: UPSTREAM) do |f|
      f.adapter Faraday.default_adapter
    end
  end

  def auth_conn
    @auth_conn ||= Faraday.new do |f|
      f.adapter Faraday.default_adapter
    end
  end
  def parse_www_authenticate(header)
    return nil unless header
    # Parse: Bearer realm="...",service="...",scope="..."
    params = {}
    header.scan(/(\w+)="([^"]+)"/) { |k, v| params[k] = v }
    params
  end

  def fetch_docker_token(realm, service, scope)
    puts "DEBUG: fetch_docker_token called"
    url = "#{realm}?service=#{service}"
    url += "&scope=#{scope}" if scope
    puts "DEBUG: Fetching token from: #{url}"
    
    begin
      resp = auth_conn.get(url)
      puts "DEBUG: Token response status: #{resp.status}, body: #{resp.body[0..200]}"
      return nil unless resp.status == 200
      
      data = JSON.parse(resp.body)
      token = data['token'] || data['access_token']
      puts "DEBUG: Extracted token: #{token ? token[0..20] : 'nil'}"
      token
    rescue => e
      puts "DEBUG: Token fetch error: #{e.class} - #{e.message}"
      puts "DEBUG: Backtrace: #{e.backtrace[0..3].join("\n")}"
      nil
    end
  end
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

# Healthcheck endpoint
get '/healthcheck' do
  status 200
  content_type 'application/json'
  body '{"status":"ok"}'
end

# GET only; extend as needed
get '/*' do
  if cached?
    meta = load_meta
    content_type(meta.dig("headers","Content-Type") || 'application/octet-stream')
    return send_file(body_path)
  end

  resp = conn.get(request.path, params, pass_headers)
  
  # Handle 401 with OAuth2 token flow
  if resp.status == 401
    auth_header = resp.headers['www-authenticate']
    puts "DEBUG: Got 401, www-authenticate: #{auth_header}"
    auth_params = parse_www_authenticate(auth_header)
    puts "DEBUG: Parsed params: #{auth_params.inspect}"
    
    if auth_params && auth_params['realm']
      puts "DEBUG: About to call fetch_docker_token"
      token = fetch_docker_token(
        auth_params['realm'],
        auth_params['service'],
        auth_params['scope']
      )
      puts "DEBUG: Fetched token result: #{token ? 'YES' : 'NO'}"
      puts "DEBUG: Token value: #{token.inspect[0..50]}" if token
      
      if token
        # Retry with token
        headers_with_auth = pass_headers.merge('Authorization' => "Bearer #{token}")
        resp = conn.get(request.path, params, headers_with_auth)
        puts "DEBUG: Retry status: #{resp.status}"
      end
    end
  end
  
  # Return response
  save_cache(resp.status, resp.headers, resp.body) if resp.status == 200
  status resp.status
  content_type resp.headers['content-type'] if resp.headers['content-type']
  body resp.body
end

run Sinatra::Application
