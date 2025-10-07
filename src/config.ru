require 'sinatra'
require 'fileutils'
require 'faraday'
require 'json'
require 'digest'
require 'slim'

require 'stack-service-base'

StackServiceBase.rack_setup self

UPSTREAM = ENV.fetch('UPSTREAM', 'https://registry-1.docker.io')
TTL      = ENV.fetch('TTL', '3600').to_i
CACHE    = ENV.fetch('CACHE_DIR', 'cache')
CLEANUP_INTERVAL = ENV.fetch('CLEANUP_INTERVAL', '300').to_i  # 5 minutes default

FileUtils.mkdir_p(CACHE)

helpers do
  # Track last cleanup time as a module method
  def self.last_cleanup
    @last_cleanup ||= Time.now - CLEANUP_INTERVAL
  end
  
  def self.last_cleanup=(time)
    @last_cleanup = time
  end
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
    
    # Trigger cleanup if interval has passed
    maybe_cleanup_cache
  end

  def maybe_cleanup_cache
    return unless should_cleanup?
    
    Thread.new do
      begin
        cleanup_expired_cache
        helpers.last_cleanup = Time.now
      rescue => e
        puts "ERROR: Background cache cleanup failed: #{e.message}"
      end
    end
  end

  def should_cleanup?
    (Time.now - helpers.last_cleanup) >= CLEANUP_INTERVAL
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

  def cleanup_expired_cache
    return unless Dir.exist?(CACHE)
    
    cleaned_count = 0
    total_size_freed = 0
    
    Dir.glob(File.join(CACHE, "*.body")).each do |body_file|
      meta_file = body_file.sub('.body', '.meta')
      
      # Check if cache entry is expired
      if File.exist?(body_file) && (Time.now - File.mtime(body_file)) >= TTL
        begin
          # Calculate size before deletion
          body_size = File.size(body_file) rescue 0
          meta_size = File.size(meta_file) rescue 0
          
          # Remove both files
          File.delete(body_file) if File.exist?(body_file)
          File.delete(meta_file) if File.exist?(meta_file)
          
          cleaned_count += 1
          total_size_freed += body_size + meta_size
          
          puts "DEBUG: Cleaned expired cache entry: #{File.basename(body_file)}"
        rescue => e
          puts "ERROR: Failed to clean #{body_file}: #{e.message}"
        end
      end
    end
    
    if cleaned_count > 0
      puts "Cache cleanup: Removed #{cleaned_count} expired entries, freed #{total_size_freed} bytes"
    end
    
    cleaned_count
  end

  def cache_stats
    return { count: 0, size: 0 } unless Dir.exist?(CACHE)
    
    total_files = 0
    total_size = 0
    expired_files = 0
    
    Dir.glob(File.join(CACHE, "*.body")).each do |body_file|
      if File.exist?(body_file)
        total_files += 1
        total_size += File.size(body_file)
        total_size += File.size(body_file.sub('.body', '.meta')) rescue 0
        
        # Check if expired
        if (Time.now - File.mtime(body_file)) >= TTL
          expired_files += 1
        end
      end
    end
    
    {
      count: total_files,
      size: total_size,
      expired: expired_files
    }
  end
end

# Dashboard route
get '/' do
  slim :index
end

# Cache management endpoints
get '/cache/stats' do
  content_type 'application/json'
  stats = cache_stats
  body JSON.dump({
    cache: {
      total_entries: stats[:count],
      total_size_bytes: stats[:size],
      total_size_mb: (stats[:size] / 1024.0 / 1024.0).round(2),
      expired_entries: stats[:expired],
      ttl_seconds: TTL,
      cache_directory: CACHE
    }
  })
end

post '/cache/cleanup' do
  content_type 'application/json'
  cleaned = cleanup_expired_cache
  body JSON.dump({
    cleanup: {
      entries_removed: cleaned,
      timestamp: Time.now.iso8601
    }
  })
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
  
  # Forward important headers
  content_type resp.headers['content-type'] if resp.headers['content-type']
  
  # Handle location header (case insensitive) - add to response headers
  location_header = resp.headers['location'] || resp.headers['Location']
  headers 'Location' => location_header if location_header
  
  # Forward Docker API version
  api_version = resp.headers['docker-distribution-api-version'] || resp.headers['Docker-Distribution-Api-Version']
  headers 'Docker-Distribution-Api-Version' => api_version if api_version
  
  body resp.body
end

run Sinatra::Application
