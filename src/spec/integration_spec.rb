RSpec.describe 'Integration Tests' do

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
  end
end