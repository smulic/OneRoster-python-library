<?php

// Load necessary modules and environment variables using the Dotenv library
require 'vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

class OneRoster {
    private $clientId;
    private $clientSecret;
    private $baseUrl;
    private $collections;

    public function __construct() {
        // Initialize with client ID and secret from environment variables
        $this->clientId = getenv('CLIENT_ID');
        $this->clientSecret = getenv('CLIENT_SECRET');
        // Define the base URL and the endpoints to access
        $this->baseUrl = "https://api.classlink.com/oneroster";
        $this->collections = ["academicSessions", "orgs", "courses", "classes", "users", "enrollments", "demographics"];
    }

    // Main method to fetch all data from each collection
    public function fetchAllData() {
        foreach ($this->collections as $collection) {
            $url = "{$this->baseUrl}/{$collection}";
            $this->fetchCollection($url);
        }
    }

    // Fetch data from a single collection with pagination
    private function fetchCollection($url) {
        $limit = 10000; // Maximum number of items per page
        $offset = 0; // Start at the beginning
        $totalCount = null; // Total number of items in the collection
        $runningTotal = 0; // Counter for items fetched
        $retries = 0; // Counter for retry attempts

        // Continue fetching until all data is retrieved
        while ($totalCount === null || $runningTotal < $totalCount) {
            $data = $this->makeRosterRequest($url, $limit, $offset);
            if ($data['status'] !== 200) {
                // Handle rate limiting and server errors
                if (in_array($data['status'], [429, 502])) {
                    $retries = $this->handleRateLimits($retries, $data['status']);
                }
                continue;
            }
            $pageData = $data['data'];
            $count = count($pageData);
            $runningTotal += $count;
            $totalCount = intval($data['headers']['x-total-count']);
            $offset += $limit;
        }
    }

    // Construct the full URL and make the HTTP GET request
    private function makeRosterRequest($url, $limit, $offset) {
        $url .= "?limit={$limit}&offset={$offset}";
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Authorization: ' . $this->buildAuthHeader()]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return ['status' => $httpCode, 'data' => json_decode($response, true), 'headers' => curl_getinfo($ch)];
    }

    // Implement exponential backoff with jitter for rate limits
    private function handleRateLimits($retries, $errorCode) {
        $waitTime = pow(2, $retries) + mt_rand(0, 1000) / 1000;
        sleep($waitTime);
        $retries += 1;
        if ($retries > 5) {
            throw new Exception("API request failed after several retries due to error $errorCode");
        }
        return $retries;
    }

    // Construct the OAuth authorization header
    private function buildAuthHeader() {
        $method = 'GET';
        $timestamp = time();
        $nonce = $this->generateNonce(10);
        $params = [
            'oauth_consumer_key' => $this->clientId,
            'oauth_signature_method' => 'HMAC-SHA256',
            'oauth_timestamp' => $timestamp,
            'oauth_nonce' => $nonce
        ];
        $baseString = $this->buildBaseString($this->baseUrl, $method, $params);
        $signature = $this->generateAuthSignature($baseString);
        return "OAuth oauth_signature=\"".urlencode($signature)."\"";
    }

    // Generate a random string (nonce) for the OAuth signature
    private function generateNonce($length) {
        $possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        $nonce = '';
        for ($i = 0; $i < $length; $i++) {
            $nonce .= $possible[rand(0, strlen($possible) - 1)];
        }
        return $nonce;
    }

    // Build the base string for the OAuth signature
    private function buildBaseString($url, $method, $params) {
        ksort($params);
        $paramStr = '';
        foreach ($params as $key => $value) {
            $paramStr .= "&" . rawurlencode($key) . "=" . rawurlencode($value);
        }
        $paramStr = ltrim($paramStr, '&');
        return $method . '&' . rawurlencode($url) . '&' . rawurlencode($paramStr);
    }

    // Generate the HMAC-SHA256 signature for OAuth
    private function generateAuthSignature($baseString) {
        $key = rawurlencode($this->clientSecret) . '&';
        return base64_encode(hash_hmac('sha256', $baseString, $key, true));
    }
}

// Usage example: create an instance and fetch all data
$roster = new OneRoster();
$roster->fetchAllData();

?>
