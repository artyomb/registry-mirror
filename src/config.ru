require 'sinatra'
require 'fileutils'
require 'faraday'
require 'json'
require 'digest'
require 'slim'
require 'sqlite3'

require 'stack-service-base'

StackServiceBase.rack_setup self

UPSTREAM = ENV.fetch('UPSTREAM', 'https://registry-1.docker.io')
TTL      = ENV.fetch('TTL', '3600').to_i
CACHE_DIR = ENV.fetch('CACHE_DIR', 'cache')
CACHE_DB = File.join(CACHE_DIR, 'registry_cache.db')
CLEANUP_INTERVAL = ENV.fetch('CLEANUP_INTERVAL', '300').to_i  # 5 minutes default
set :last_cleanup, Time.now - CLEANUP_INTERVAL

FileUtils.mkdir_p(CACHE_DIR)

# Initialize SQLite database with shared connection
DB = SQLite3::Database.new(CACHE_DB)
DB.busy_timeout = 5000  # 5 second timeout for locks
DB.execute <<-SQL
  CREATE TABLE IF NOT EXISTS cache_entries (
    uri TEXT PRIMARY KEY,
    image_name TEXT,
    tag TEXT,
    cache_time INTEGER,
    status INTEGER,
    content_type TEXT,
    headers TEXT,
    body BLOB
  );
SQL

helpers do
  # Track last cleanup time via Sinatra settings to avoid helper scope lookups
  def last_cleanup
    settings.last_cleanup
  end

  def update_last_cleanup(time)
    settings.last_cleanup = time
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

  def upstream_request(method, path, params = {}, headers = {})
    if method == :get
      conn.get(path, params, headers)
    else
      conn.run_request(method, path, nil, headers)
    end
  end

  def fetch_with_auth(method, path, params = {}, headers = {})
    resp = upstream_request(method, path, params, headers)

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
          headers_with_auth = headers.merge('Authorization' => "Bearer #{token}")
          resp = upstream_request(method, path, params, headers_with_auth)
          puts "DEBUG: Retry status: #{resp.status}"
        end
      end
    end

    resp
  end
  def parse_docker_uri(uri)
    # Parse Docker registry URI to extract image_name and tag
    # Examples:
    # /v2/library/postgres/manifests/16 -> image_name: "library/postgres", tag: "16"
    # /v2/library/alpine/blobs/sha256:... -> image_name: "library/alpine", tag: nil
    # /v2/ -> image_name: nil, tag: nil
    
    return { image_name: nil, tag: nil } unless uri.start_with?('/v2/')
    
    parts = uri.split('/').reject(&:empty?)
    return { image_name: nil, tag: nil } if parts.length < 3
    
    # Remove 'v2' prefix
    parts.shift
    
    if parts.length >= 3
      if parts[-2] == 'manifests'
        # Manifest request: /v2/namespace/repo/manifests/tag
        image_name = parts[0..-3].join('/')
        tag = parts[-1]
      elsif parts[-2] == 'blobs'
        # Blob request: /v2/namespace/repo/blobs/digest
        image_name = parts[0..-3].join('/')
        tag = nil
      else
        # Other requests
        image_name = parts.join('/')
        tag = nil
      end
    else
      image_name = parts.join('/')
      tag = nil
    end
    
    { image_name: image_name, tag: tag }
  end

  def cached?
    result = DB.execute(
      "SELECT cache_time FROM cache_entries WHERE uri = ? AND cache_time > ?",
      [request.fullpath, Time.now.to_i - TTL]
    )
    !result.empty?
  end

  def cache_get
    result = DB.execute(
      "SELECT status, headers, body FROM cache_entries WHERE uri = ? AND cache_time > ?",
      [request.fullpath, Time.now.to_i - TTL]
    ).first
    
    return nil unless result
    
    status, headers_json, body = result
    headers = JSON.parse(headers_json)
    [status, headers, body]
  end

  def cache_entry_for(image_name, tag)
    DB.execute(
      "SELECT uri, cache_time, status, content_type, headers, body FROM cache_entries WHERE image_name = ? AND tag = ? ORDER BY cache_time DESC LIMIT 1",
      [image_name, tag]
    ).first
  end

  def save_cache(status, headers, body)
    parsed = parse_docker_uri(request.fullpath)

    # Skip caching system/API and non-tag entries to avoid polluting the cache list
    return if parsed[:image_name].nil? || parsed[:tag].nil?
    
    DB.execute(
      "INSERT OR REPLACE INTO cache_entries (uri, image_name, tag, cache_time, status, content_type, headers, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [
        request.fullpath,
        parsed[:image_name],
        parsed[:tag],
        Time.now.to_i,
        status,
        headers['content-type'],
        JSON.dump({ "Content-Type" => headers['content-type'] }),
        body
      ]
    )
    
    # Trigger cleanup if interval has passed
    maybe_cleanup_cache
  end

  def maybe_cleanup_cache
    return unless should_cleanup?
    
    Thread.new do
      begin
        cleanup_expired_cache
        update_last_cleanup(Time.now)
      rescue => e
        puts "ERROR: Background cache cleanup failed: #{e.message}"
      end
    end
  end

  def should_cleanup?
    (Time.now - last_cleanup) >= CLEANUP_INTERVAL
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
    # Count expired entries before deletion
    expired_count = DB.execute(
      "SELECT COUNT(*) FROM cache_entries WHERE cache_time <= ?",
      [Time.now.to_i - TTL]
    ).first[0]
    
    # Calculate total size freed (approximate)
    total_size_freed = DB.execute(
      "SELECT SUM(LENGTH(body)) FROM cache_entries WHERE cache_time <= ?",
      [Time.now.to_i - TTL]
    ).first[0] || 0
    
    # Delete expired entries
    DB.execute(
      "DELETE FROM cache_entries WHERE cache_time <= ?",
      [Time.now.to_i - TTL]
    )
    
    if expired_count > 0
      puts "Cache cleanup: Removed #{expired_count} expired entries, freed #{total_size_freed} bytes"
    end
    
    expired_count
  end

  def format_time_ago(timestamp)
    seconds_ago = Time.now.to_i - timestamp
    if seconds_ago < 60
      "#{seconds_ago}s ago"
    elsif seconds_ago < 3600
      "#{seconds_ago / 60}m ago"
    elsif seconds_ago < 86400
      "#{seconds_ago / 3600}h ago"
    else
      "#{seconds_ago / 86400}d ago"
    end
  end

  def format_bytes(bytes)
    return "0 B" if bytes == 0
    
    units = ['B', 'KB', 'MB', 'GB']
    size = bytes.to_f
    unit_index = 0
    
    while size >= 1024 && unit_index < units.length - 1
      size /= 1024
      unit_index += 1
    end
    
    "#{size.round(2)} #{units[unit_index]}"
  end

  def cache_stats
    # Get total entries
    total_entries = DB.execute("SELECT COUNT(*) FROM cache_entries").first[0]
    
    # Get total size
    total_size = DB.execute("SELECT SUM(LENGTH(body)) FROM cache_entries").first[0] || 0
    
    # Get expired entries
    expired_entries = DB.execute(
      "SELECT COUNT(*) FROM cache_entries WHERE cache_time <= ?",
      [Time.now.to_i - TTL]
    ).first[0]
    
    # Get image breakdown
    image_stats = DB.execute(
      "SELECT image_name, COUNT(*) as count, SUM(LENGTH(body)) as size FROM cache_entries WHERE image_name IS NOT NULL GROUP BY image_name ORDER BY count DESC LIMIT 10"
    )
    
    # Get detailed entries for dashboard preview (top 5 recent)
    detailed_entries = DB.execute(
      "SELECT uri, image_name, tag, cache_time, status, LENGTH(body) as size FROM cache_entries ORDER BY cache_time DESC LIMIT 5"
    ).map do |row|
      {
        uri: row[0],
        image_name: row[1] || 'N/A',
        tag: row[2] || 'N/A',
        cached_ago: format_time_ago(row[3]),
        status: row[4],
        size_formatted: format_bytes(row[5])
      }
    end
    
    {
      count: total_entries,
      size: total_size,
      expired: expired_entries,
      images: image_stats.map { |row| { name: row[0], count: row[1], size: row[2] } },
      detailed_entries: detailed_entries
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
      cache_database: CACHE_DB,
      top_images: stats[:images],
      detailed_entries: stats[:detailed_entries]
    }
  })
end

get '/cache/entries' do
  content_type 'application/json'
  page = (params[:page] || 1).to_i
  per_page = (params[:per_page] || 10).to_i
  offset = (page - 1) * per_page
  
  # Get total count
  total_count = DB.execute("SELECT COUNT(*) FROM cache_entries").first[0]
  
  # Get paginated entries with details
  entries = DB.execute(
    "SELECT uri, image_name, tag, cache_time, status, content_type, LENGTH(body) as size, body
     FROM cache_entries 
     ORDER BY cache_time DESC 
     LIMIT ? OFFSET ?",
    [per_page, offset]
  )
  
  body JSON.dump({
    entries: entries.map do |row|
      expired = row[3] <= Time.now.to_i - TTL
      digest = nil
      if row[1] && row[2] && row[7] && row[4] == 200
        digest = "sha256:#{Digest::SHA256.hexdigest(row[7])}"
      end
      {
        uri: row[0],
        image_name: row[1] || 'N/A',
        tag: row[2] || 'N/A', 
        cache_time: row[3],
        cached_ago: format_time_ago(row[3]),
        expired: expired,
        status: row[4],
        content_type: row[5],
        size_bytes: row[6],
        size_formatted: format_bytes(row[6]),
        digest: digest
      }
    end,
    pagination: {
      page: page,
      per_page: per_page,
      total_count: total_count,
      total_pages: (total_count.to_f / per_page).ceil,
      has_next: page * per_page < total_count,
      has_prev: page > 1
    }
  })
end

get '/cache/image_status' do
  content_type 'application/json'
  image = params[:image]
  tag = params[:tag]

  if image.to_s.strip.empty? || tag.to_s.strip.empty?
    status 400
    return JSON.dump({ error: 'image and tag are required' })
  end

  manifest_path = "/v2/#{image}/manifests/#{tag}"
  accept_header = params[:accept] || 'application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json'

  upstream_resp = fetch_with_auth(:head, manifest_path, {}, { 'Accept' => accept_header })
  if upstream_resp.status == 405
    upstream_resp = fetch_with_auth(:get, manifest_path, {}, { 'Accept' => accept_header })
  end

  upstream_digest = upstream_resp.headers['docker-content-digest'] || upstream_resp.headers['Docker-Content-Digest']
  upstream_last_modified = upstream_resp.headers['last-modified'] || upstream_resp.headers['Last-Modified']

  cached_row = cache_entry_for(image, tag)
  cached_data = nil
  if cached_row
    uri, cache_time, status_code, content_type, headers_json, body = cached_row
    cached_digest = nil
    if body && status_code == 200
      cached_digest = "sha256:#{Digest::SHA256.hexdigest(body)}"
    end
    cached_data = {
      uri: uri,
      status: status_code,
      content_type: content_type,
      cache_time: cache_time,
      cached_ago: format_time_ago(cache_time),
      expired: cache_time <= Time.now.to_i - TTL,
      digest: cached_digest
    }
  end

  response = {
    image: image,
    tag: tag,
    request_path: manifest_path,
    cache: cached_data,
    upstream: {
      status: upstream_resp.status,
      content_type: upstream_resp.headers['content-type'],
      digest: upstream_digest,
      last_modified: upstream_last_modified
    },
    comparison: {
      cache_present: !cached_data.nil?,
      cache_expired: cached_data ? cached_data[:expired] : nil,
      digest_matches: (cached_data && upstream_digest) ? (cached_data[:digest] == upstream_digest) : nil
    }
  }

  body JSON.dump(response)
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

post '/cache/cleanup_all' do
  content_type 'application/json'
  total = DB.execute("SELECT COUNT(*) FROM cache_entries").first[0]
  DB.execute("DELETE FROM cache_entries")
  body JSON.dump({
    cleanup: {
      entries_removed: total,
      timestamp: Time.now.iso8601
    }
  })
end

post '/cache/refresh' do
  content_type 'application/json'
  image = params[:image]
  tag = params[:tag]

  if image.to_s.strip.empty? || tag.to_s.strip.empty?
    status 400
    return JSON.dump({ error: 'image and tag are required' })
  end

  manifest_path = "/v2/#{image}/manifests/#{tag}"
  accept_header = params[:accept] || 'application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json'

  resp = fetch_with_auth(:get, manifest_path, {}, { 'Accept' => accept_header })
  save_cache(resp.status, resp.headers, resp.body) if resp.status == 200

  body JSON.dump({
    refresh: {
      image: image,
      tag: tag,
      status: resp.status,
      cached: resp.status == 200,
      timestamp: Time.now.iso8601
    }
  })
end

post '/cache/remove' do
  content_type 'application/json'
  image = params[:image]
  tag = params[:tag]

  if image.to_s.strip.empty? || tag.to_s.strip.empty?
    status 400
    return JSON.dump({ error: 'image and tag are required' })
  end

  removed = DB.execute(
    "DELETE FROM cache_entries WHERE image_name = ? AND tag = ?",
    [image, tag]
  )

  body JSON.dump({
    remove: {
      image: image,
      tag: tag,
      entries_removed: removed,
      timestamp: Time.now.iso8601
    }
  })
end

# GET only; extend as needed
get '/*' do
  if cached?
    status_code, headers, body = cache_get
    status status_code
    content_type(headers["Content-Type"] || 'application/octet-stream')
    return body
  end

  resp = fetch_with_auth(:get, request.path, params, pass_headers)
  
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
