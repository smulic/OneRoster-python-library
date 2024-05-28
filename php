<?php
require 'vendor/autoload.php';
use Dotenv\Dotenv;
use GuzzleHttp\Client;

class OneRoster {
    private $client_id;
    private $client_secret;
    private $base_url;

    // Page size for API requests
    const PAGE_SIZE = 10000;
    // Endpoints to pull data from
    const ENDPOINTS = [
        "/academicSessions",
        "/orgs",
        "/courses",
        "/classes",
        "/users",
        "/enrollments",
        "/demographics"
    ];

    public function __construct() {
        // Load environment variables from .env file
        $dotenv = Dotenv::createImmutable(__DIR__);
        $dotenv->load();

        // Initialize the OneRoster client with client ID and secret
        $this->client_id = $_ENV['CLIENT_ID'];
        $this->client_secret = $_ENV['CLIENT_SECRET'];
        $this->base_url = $_ENV['BASE_URL'];
    }

    public function makeRosterRequest(string $endpoint, int $limit = self::PAGE_SIZE, int $offset = 0): array {
        /**
         * Make a request to the specified endpoint with pagination parameters.
         *
         * @param string $endpoint The API endpoint to request data from
         * @param int $limit Number of records per page
         * @param int $offset Offset for pagination
         * @return array A dictionary containing the status code, response data, and headers
         */
        
        // Construct the URL with pagination parameters
        $url = "{$this->base_url}{$endpoint}?limit={$limit}&offset={$offset}";
        // Generate timestamp and nonce for OAuth
        $timestamp = time();
        $nonce = $this->generateNonce(strlen((string)$timestamp));

        // OAuth parameters
        $oauth_params = [
            'oauth_consumer_key' => $this->client_id,
            'oauth_signature_method' => 'HMAC-SHA256',
            'oauth_timestamp' => $timestamp,
            'oauth_nonce' => $nonce
        ];

        // Split URL into base URL and parameters
        list($base_url, $url_params) = $this->splitUrl($url);
        // Merge OAuth parameters with URL parameters
        $all_params = array_merge($oauth_params, $url_params);

        // Create the base string for the OAuth signature
        $base_string = $this->buildBaseString($base_url, 'GET', $all_params);
        // Create the composite key for HMAC
        $composite_key = rawurlencode($this->client_secret) . "&";
        // Generate the OAuth signature
        $auth_signature = $this->generateAuthSignature($base_string, $composite_key);
        $oauth_params["oauth_signature"] = $auth_signature;

        // Build the OAuth authorization header
        $auth_header = $this->buildAuthHeader($oauth_params);

        // Make the GET request to the API
        return $this->makeGetRequest($base_url, $auth_header, $url_params);
    }

    public function pullCompleteDataSet(): array {
        /**
         * Pull the complete data set from all defined endpoints.
         *
         * @return array A dictionary containing data from all endpoints
         */
        
        $all_data = [];
        // Loop through each endpoint to pull all data
        foreach (self::ENDPOINTS as $endpoint) {
            $all_data[$endpoint] = $this->pullAllData($endpoint);
        }
        return $all_data;
    }

    private function pullAllData(string $endpoint): array {
        /**
         * Pull all data from a specified endpoint using pagination.
         *
         * @param string $endpoint The API endpoint to pull data from
         * @return array A list of all records from the endpoint
         */
        
        $data = [];
        $offset = 0;
        $total_count = null;

        while (count($data) != $total_count) {
            // Make the API request with retries
            $response = $this->makeRequestWithRetries($endpoint, $offset);
            if ($response["status_code"] != 200) {
                $code = $response["status_code"];
                echo "Error in request to endpoint $endpoint - $code\n";
                break;
            }

            // Get the current page of data
            $response_name = ltrim($endpoint, '/');
            $current_data = $response["response"][$response_name];
            $data = array_merge($data, $current_data);

            // Set total_count on the first request
            if (is_null($total_count)) {
                $total_count = intval($response["headers"]["x-total-count"] ?? count($current_data));
            }

            // Update the offset for the next page
            $offset += self::PAGE_SIZE;
        }

        return $data;
    }

    private function makeRequestWithRetries(string $endpoint, int $limit = self::PAGE_SIZE, int $offset = 0): array {
        /**
         * Make a request with retries in case of rate limiting or server errors.
         *
         * @param string $endpoint The API endpoint to request data from
         * @param int $limit Number of records per page
         * @param int $offset Offset for pagination
         * @return array A dictionary containing the status code, response data, and headers
         */
        
        $retries = 0;
        $max_retries = 3;
        $base_wait_time = 1;

        while ($retries < $max_retries) {
            $response = $this->makeRosterRequest($endpoint, $limit, $offset);
            if ($response["status_code"] == 200) {
                return $response;
            } elseif (in_array($response["status_code"], [429, 502])) {
                // Apply exponential backoff with jitter
                $wait_time = $base_wait_time * (2 ** $retries) + rand(0, 1000) / 1000;
                sleep($wait_time);
                $retries++;
            } else {
                return $response;
            }
        }

        return ["status_code" => $response["status_code"], "response" => "Max retries exceeded"];
    }

    private function generateNonce(int $length): string {
        /**
         * Generate a random nonce.
         *
         * @param int $length Length of the nonce
         * @return string The generated nonce
         */
        
        $characters = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        $result = '';
        for ($i = 0; $i < $length; $i++) {
            $result .= $characters[rand(0, strlen($characters) - 1)];
        }
        return $result;
    }

    private function splitUrl(string $url): array {
        /**
         * Split the URL into base URL and parameters.
         *
         * @param string $url The URL to split
         * @return array The base URL and parameters dictionary
         */
        
        $parts = parse_url($url);
        $base_url = "{$parts['scheme']}://{$parts['host']}{$parts['path']}";
        $url_params = [];
        if (isset($parts['query'])) {
            parse_str($parts['query'], $url_params);
        }
        return [$base_url, $url_params];
    }

    private function buildBaseString(string $base_url, string $method, array $params): string {
        /**
         * Generate the base string for OAuth signature generation.
         *
         * @param string $base_url The base URL
         * @param string $method The HTTP method
         * @param array $params The URL and OAuth parameters
         * @return string The base string for OAuth signature generation
         */
        
        ksort($params);
        $encoded_params = [];
        foreach ($params as $key => $value) {
            $encoded_params[] = rawurlencode($key) . '=' . rawurlencode($value);
        }
        $param_string = implode('&', $encoded_params);
        return "$method&" . rawurlencode($base_url) . "&" . rawurlencode($param_string);
    }

    private function generateAuthSignature(string $base_string, string $composite_key): string {
        /**
         * Generate the OAuth signature.
         *
         * @param string $base_string The base string for the OAuth signature
         * @param string $composite_key The composite key for HMAC
         * @return string The generated OAuth signature
         */
        
        $digest = hash_hmac('sha256', $base_string, $composite_key, true);
        return base64_encode($digest);
    }

    private function buildAuthHeader(array $oauth): string {
        /**
         * Generate the OAuth authorization header.
         *
         * @param array $oauth OAuth parameters
         * @return string The OAuth authorization header
         */
        
        $header_params = [];
        foreach ($oauth as $key => $value) {
            $header_params[] = "$key=\"" . rawurlencode($value) . "\"";
        }
        return 'OAuth ' . implode(', ', $header_params);
    }

    private function makeGetRequest(string $url, string $auth_header, array $params): array {
        /**
         * Make a GET request to the API.
         *
         * @param string $url The base URL of the request
         * @param string $auth_header The OAuth authorization header
         * @param array $params URL parameters
         * @return array A dictionary containing the status code, response data, and headers
         */
        
        try {
            $client = new Client();
            $response = $client->request('GET', $url, [
                'headers' => ['Authorization' => $auth_header],
                'query' => $params
            ]);
            $body = json_decode($response->getBody(), true);
            return [
                'status_code' => $response->getStatusCode(),
                'response' => $body,
                'headers' => $response->getHeaders()
            ];
        } catch (Exception $e) {
            return ['status_code' => 0, 'response' => "An error occurred: " . $e->getMessage()];
        }
    }
}

if (php_sapi_name() == "cli") {
    $roster = new OneRoster();
    $data = $roster->pullCompleteDataSet();
    print_r($data);
}
?>
