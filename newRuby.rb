require 'net/http'
require 'uri'
require 'json'
require 'openssl'
require 'base64'
require 'cgi'
require 'securerandom'
require 'dotenv/load'

class OneRoster
  # Endpoints to pull data from
  ENDPOINTS = [
    "/academicSessions",
    "/orgs",
    "/courses",
    "/classes",
    "/users",
    "/enrollments",
    "/demographics"
  ].freeze

  # Page size for API requests
  PAGE_SIZE = 10_000

  def initialize
    # Initialize the OneRoster client with client ID and secret
    @client_id = ENV['CLIENT_ID']
    @client_secret = ENV['CLIENT_SECRET']
    # Base URL for all API requests
    @base_url = ENV['BASE_URL']
  end

  def make_roster_request(endpoint, limit = PAGE_SIZE, offset = 0)
    """
    Make a request to the specified endpoint with pagination parameters.

    :param endpoint: The API endpoint to request data from
    :param limit: Number of records per page
    :param offset: Offset for pagination
    :return: A dictionary containing the status code, response data, and headers
    """
    # Construct the URL with pagination parameters
    url = "#{@base_url}#{endpoint}?limit=#{limit}&offset=#{offset}"
    # Generate timestamp and nonce for OAuth
    timestamp = Time.now.to_i.to_s
    nonce = generate_nonce(timestamp.length)

    # OAuth parameters
    oauth_params = {
      'oauth_consumer_key' => @client_id,
      'oauth_signature_method' => 'HMAC-SHA256',
      'oauth_timestamp' => timestamp,
      'oauth_nonce' => nonce
    }

    # Split URL into base URL and parameters
    base_url, url_params = split_url(url)
    # Merge OAuth parameters with URL parameters
    all_params = merge_dicts(oauth_params, url_params)

    # Create the base string for the OAuth signature
    base_string = build_base_string(base_url, 'GET', all_params)
    # Create the composite key for HMAC
    composite_key = CGI.escape(@client_secret) + "&"
    # Generate the OAuth signature
    auth_signature = generate_auth_signature(base_string, composite_key)
    oauth_params["oauth_signature"] = auth_signature

    # Build the OAuth authorization header
    auth_header = build_auth_header(oauth_params)

    # Make the GET request to the API
    make_get_request(base_url, auth_header, url_params)
  end

  def pull_complete_data_set
    """
    Pull the complete data set from all defined endpoints.

    :return: A dictionary containing data from all endpoints
    """
    all_data = {}
    # Loop through each endpoint to pull all data
    ENDPOINTS.each do |endpoint|
      all_data[endpoint] = pull_all_data(endpoint)
    end
    all_data
  end

  def pull_all_data(endpoint)
    """
    Pull all data from a specified endpoint using pagination.

    :param endpoint: The API endpoint to pull data from
    :return: A list of all records from the endpoint
    """
    data = []
    offset = 0
    total_count = nil

    while data.length != total_count
      # Make the API request with retries
      response = make_request_with_retries(endpoint, offset: offset)
      if response[:status_code] != 200
        puts "Error in request to endpoint #{endpoint} - #{response[:status_code]}"
        break
      end

      # Get the current page of data
      response_name = endpoint.sub("/", "")
      current_data = response[:response][response_name]
      data.concat(current_data)

      # Set total_count on the first request
      if total_count.nil?
       total_count = response[:headers]['x-total-count'][0].to_i
      end

      # Update the offset for the next page
      offset += PAGE_SIZE
    end

    data
  end

  def make_request_with_retries(endpoint, limit: PAGE_SIZE, offset: 0)
    """
    Make a request with retries in case of rate limiting or server errors.

    :param endpoint: The API endpoint to request data from
    :param limit: Number of records per page
    :param offset: Offset for pagination
    :return: A dictionary containing the status code, response data, and headers
    """
    retries = 0
    max_retries = 3
    base_wait_time = 1

    while retries < max_retries
      response = make_roster_request(endpoint, limit, offset)
      if response[:status_code] == 200
        return response
      elsif [429, 502].include?(response[:status_code])
        # Apply exponential backoff with jitter
        wait_time = base_wait_time * (2**retries) + rand(0..1000) / 1000.0
        sleep(wait_time)
        retries += 1
      else
        return response
      end
    end

    { status_code: response[:status_code], response: 'Max retries exceeded' }
  end

  private

  def merge_dicts(oauth, params)
    """
    Merge OAuth and URL parameter dictionaries.

    :param oauth: OAuth parameters
    :param params: URL parameters
    :return: A merged dictionary of parameters
    """
    oauth.merge(params)
  end

  def generate_nonce(length)
    """
    Generate a random nonce.

    :param length: Length of the nonce
    :return: The generated nonce
    """
    SecureRandom.alphanumeric(length)
  end

  def split_url(url)
    """
    Split the URL into base URL and parameters.

    :param url: The URL to split
    :return: The base URL and parameters dictionary
    """
    uri = URI.parse(url)
    base_url = "#{uri.scheme}://#{uri.host}#{uri.path}"
    url_params = CGI.parse(uri.query || '').transform_values(&:first)
    [base_url, url_params]
  end

  def build_base_string(base_url, method, params)
    """
    Generate the base string for OAuth signature generation.

    :param base_url: The base URL
    :param method: The HTTP method
    :param params: The URL and OAuth parameters
    :return: The base string for OAuth signature generation
    """
    encoded_params = params.sort.map { |k, v| "#{k}=#{CGI.escape(v.to_s)}" }.join('&')
    "#{method}&#{CGI.escape(base_url)}&#{CGI.escape(encoded_params)}"
  end

  def generate_auth_signature(base_string, composite_key)
    """
    Generate the OAuth signature.

    :param base_string: The base string for the OAuth signature
    :param composite_key: The composite key for HMAC
    :return: The generated OAuth signature
    """
    digest = OpenSSL::HMAC.digest('sha256', composite_key, base_string)
    Base64.strict_encode64(digest)
  end

  def build_auth_header(oauth)
    """
    Generate the OAuth authorization header.

    :param oauth: OAuth parameters
    :return: The OAuth authorization header
    """
    header_params = oauth.map { |k, v| "#{k}=\"#{CGI.escape(v)}\"" }.join(', ')
    "OAuth #{header_params}"
  end

  def make_get_request(url, auth_header, params)
    """
    Make a GET request to the API.

    :param url: The base URL of the request
    :param auth_header: The OAuth authorization header
    :param params: URL parameters
    :return: A dictionary containing the status code, response data, and headers
    """
    uri = URI(url)
    uri.query = URI.encode_www_form(params) if params && !params.empty?

    request = Net::HTTP::Get.new(uri)
    request['Authorization'] = auth_header

    response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') do |http|
      http.request(request)
    end

    {
      status_code: response.code.to_i,
      response: JSON.parse(response.body),
      headers: response.to_hash
    }
  rescue StandardError => e
    { status_code: 0, response: "An error occurred: #{e.message}" }
  end
end

if __FILE__ == $0
  roster = OneRoster.new
  data = roster.pull_complete_data_set
  puts data
end
