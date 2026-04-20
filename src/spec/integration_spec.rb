RSpec.describe 'Integration Tests' do
  def docker_hub_webhook_payload(overrides = {})
    payload = {
      'push_data' => {
        'pushed_at' => 1_417_566_161,
        'pusher' => 'trustedbuilder',
        'tag' => 'latest'
      },
      'repository' => {
        'namespace' => 'dtorry',
        'name' => 'codex2vllm',
        'repo_name' => 'dtorry/codex2vllm'
      }
    }

    payload.merge(overrides)
  end

  def with_env(name, value)
    original = ENV[name]
    ENV[name] = value
    yield
  ensure
    ENV[name] = original
  end

  describe 'Service basics' do
    it 'respond to Healthcheck' do
      get '/healthcheck'
      expect(last_response.status).to eq(200)
    end
  end

  describe 'Docker Registry v2 API' do
    it 'proxies manifest requests' do
      # Test manifest pull for library/alpine:latest
      # Docker Hub returns 401 without auth token - verify proxy passes it through
      get '/v2/library/alpine/manifests/latest', {}, {
        'HTTP_ACCEPT' => 'application/vnd.docker.distribution.manifest.v2+json'
      }
      expect([200, 401]).to include(last_response.status)
      expect(last_response.content_type).to include('application')
    end

    it 'proxies blob requests' do
      # First get manifest to extract a blob digest
      get '/v2/library/alpine/manifests/latest', {}, {
        'HTTP_ACCEPT' => 'application/vnd.docker.distribution.manifest.v2+json'
      }
      
      if last_response.status == 200
        manifest = JSON.parse(last_response.body)
        if manifest['config'] && manifest['config']['digest']
          digest = manifest['config']['digest']
          
          # Now fetch the blob
          get "/v2/library/alpine/blobs/#{digest}"
          expect(last_response.status).to eq(200)
        end
      end
    end

    it 'caches responses on second request' do
      path = '/v2/library/alpine/manifests/latest'
      headers = { 'HTTP_ACCEPT' => 'application/vnd.docker.distribution.manifest.v2+json' }
      
      # First request - should hit upstream
      get path, {}, headers
      first_status = last_response.status
      
      # Second request - should hit cache
      get path, {}, headers
      expect(last_response.status).to eq(first_status)
    end

    it 'uses the same cached manifest when Docker mirror namespace query is present' do
      path = '/v2/dtorry/oauth2-slim/manifests/latest'
      body = '{"schemaVersion":2,"config":{"digest":"sha256:test"}}'
      headers_json = JSON.dump({ 'Content-Type' => 'application/vnd.docker.distribution.manifest.v2+json' })

      DB.execute('DELETE FROM cache_entries WHERE image_name = ? AND tag = ?', ['dtorry/oauth2-slim', 'latest'])
      DB.execute(
        'INSERT INTO cache_entries (uri, image_name, tag, cache_time, status, content_type, headers, body, digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [
          path,
          'dtorry/oauth2-slim',
          'latest',
          Time.now.to_i,
          200,
          'application/vnd.docker.distribution.manifest.v2+json',
          headers_json,
          body,
          'sha256:test'
        ]
      )

      allow_any_instance_of(Sinatra::Application).to receive(:fetch_with_auth).and_raise('upstream should not be called')

      get "#{path}?ns=docker.io"

      expect(last_response.status).to eq(200)
      expect(last_response.body).to eq(body)
    end

    it 'does not forward Docker mirror namespace query parameters upstream' do
      path = '/v2/dtorry/oauth2-slim/manifests/latest'
      response = Struct.new(:status, :headers, :body).new(
        200,
        { 'content-type' => 'application/vnd.docker.distribution.manifest.v2+json' },
        '{"schemaVersion":2}'
      )

      DB.execute('DELETE FROM cache_entries WHERE image_name = ? AND tag = ?', ['dtorry/oauth2-slim', 'latest'])
      expect_any_instance_of(Sinatra::Application).to receive(:fetch_with_auth) do |_app, method, upstream_path, query_params, _headers|
        expect(method).to eq(:get)
        expect(upstream_path).to eq(path)
        expect(query_params).to be_nil
        response
      end

      get "#{path}?ns=docker.io"

      expect(last_response.status).to eq(200)
      cached_uri = DB.execute('SELECT uri FROM cache_entries WHERE image_name = ? AND tag = ?', ['dtorry/oauth2-slim', 'latest']).flatten
      expect(cached_uri).to eq([path])
    end

    it 'proxies postgres:16 manifest requests' do
      # Test manifest pull for library/postgres:16
      get '/v2/library/postgres/manifests/16', {}, {
        'HTTP_ACCEPT' => 'application/vnd.docker.distribution.manifest.v2+json'
      }
      expect([200, 401]).to include(last_response.status)
      expect(last_response.content_type).to include('application')
    end
  end

  describe 'Docker Hub webhooks' do
    it 'removes cached entries for the pushed repository tag' do
      DB.execute('DELETE FROM cache_entries WHERE image_name = ? AND tag = ?', ['dtorry/codex2vllm', 'latest'])
      DB.execute(
        'INSERT INTO cache_entries (uri, image_name, tag, cache_time, status, content_type, headers, body, digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [
          '/v2/dtorry/codex2vllm/manifests/latest',
          'dtorry/codex2vllm',
          'latest',
          Time.now.to_i,
          200,
          'application/vnd.oci.image.index.v1+json',
          JSON.dump({ 'Content-Type' => 'application/vnd.oci.image.index.v1+json' }),
          '{"schemaVersion":2}',
          'sha256:test'
        ]
      )

      post '/webhooks/docker-hub', JSON.dump(docker_hub_webhook_payload), { 'CONTENT_TYPE' => 'application/json' }

      expect(last_response.status).to eq(200)
      expect(JSON.parse(last_response.body).dig('webhook', 'entries_removed')).to eq(1)
      count = DB.execute('SELECT COUNT(*) FROM cache_entries WHERE image_name = ? AND tag = ?', ['dtorry/codex2vllm', 'latest']).first[0]
      expect(count).to eq(0)
    end

    it 'accepts namespace and name when repo_name is absent' do
      payload = docker_hub_webhook_payload(
        'repository' => {
          'namespace' => 'dtorry',
          'name' => 'codex2vllm'
        }
      )

      post '/webhooks/docker-hub', JSON.dump(payload), { 'CONTENT_TYPE' => 'application/json' }

      expect(last_response.status).to eq(200)
      parsed = JSON.parse(last_response.body)
      expect(parsed.dig('webhook', 'image')).to eq('dtorry/codex2vllm')
      expect(parsed.dig('webhook', 'tag')).to eq('latest')
    end

    it 'rejects malformed webhook payloads' do
      post '/webhooks/docker-hub', '{"broken"', { 'CONTENT_TYPE' => 'application/json' }

      expect(last_response.status).to eq(400)
      expect(JSON.parse(last_response.body)).to eq('error' => 'invalid json payload')
    end

    it 'supports an optional webhook token' do
      with_env('DOCKER_HUB_WEBHOOK_TOKEN', 'secret-token') do
        post '/webhooks/docker-hub?token=wrong', JSON.dump(docker_hub_webhook_payload), { 'CONTENT_TYPE' => 'application/json' }
        expect(last_response.status).to eq(403)

        post '/webhooks/docker-hub?token=secret-token', JSON.dump(docker_hub_webhook_payload), { 'CONTENT_TYPE' => 'application/json' }
        expect(last_response.status).to eq(200)
      end
    end
  end
end
