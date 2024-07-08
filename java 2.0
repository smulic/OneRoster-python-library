package com.classlink.roster;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

public class OneRoster {
    private final String clientId;
    private final String clientSecret;
    private static final int PAGE_SIZE = 10000;
    private static final int MAX_RETRIES = 5;

    public OneRoster(String clientId, String clientSecret) {
        this.clientId = Objects.requireNonNull(clientId, "ClientId cannot be null");
        this.clientSecret = Objects.requireNonNull(clientSecret, "ClientSecret cannot be null");
    }

    /**
     * Pull all data for specified endpoints.
     *
     * @return A map of endpoint to its corresponding data list.
     */
    public Map<String, List<Map<String, Object>>> pullAllData() {
        List<String> endpoints = List.of(
            "/academicSessions", "/orgs", "/courses", 
            "/classes", "/users", "/enrollments", "/demographics"
        );

        Map<String, List<Map<String, Object>>> allData = new HashMap<>();
        for (String endpoint : endpoints) {
            allData.put(endpoint, fetchData(endpoint));
        }

        return allData;
    }

    /**
     * Fetch data for a specific endpoint, handling pagination.
     *
     * @param endpoint The API endpoint to fetch data from.
     * @return A list of records fetched from the endpoint.
     */
    private List<Map<String, Object>> fetchData(String endpoint) {
        List<Map<String, Object>> allRecords = new ArrayList<>();
        int offset = 0;
        int totalCount = 0;

        do {
            String url = String.format("https://api.example.com%s?limit=%d&offset=%d", endpoint, PAGE_SIZE, offset);
            OneRosterResponse response = makeRosterRequest(url);

            if (response.getStatusCode() == 429 || response.getStatusCode() == 502) {
                handleRateLimitingAndServerErrors(response.getStatusCode());
                continue;
            }

            if (response.getStatusCode() == 200) {
                List<Map<String, Object>> pageData = parseResponse(response.getResponse());
                allRecords.addAll(pageData);
                offset += PAGE_SIZE;
                totalCount = Integer.parseInt(response.getHeaders().getOrDefault("x-total-count", "0"));
            } else {
                throw new RuntimeException("Error fetching data: " + response.getResponse());
            }
        } while (allRecords.size() < totalCount);

        return allRecords;
    }

    /**
     * Make a roster request with OAuth 1.0a authorization.
     *
     * @param url The URL to make the request to.
     * @return The response of the request.
     */
    private OneRosterResponse makeRosterRequest(String url) {
        String timestamp = Long.toString(System.currentTimeMillis() / 1000);
        String nonce = generateNonce(32);

        Map<String, String> oauth = new LinkedHashMap<>();
        oauth.put("oauth_consumer_key", this.clientId);
        oauth.put("oauth_signature_method", "HMAC-SHA256");
        oauth.put("oauth_timestamp", timestamp);
        oauth.put("oauth_nonce", nonce);

        String[] urlPieces = url.split("\\?");
        Map<String, String> allParams = urlPieces.length == 2 ? sortAllParams(oauth, paramsToMap(urlPieces[1])) : sortAllParams(oauth, new HashMap<>());

        String baseInfo = buildBaseString(urlPieces[0], "GET", allParams);
        String compositeKey = encodeURL(clientSecret) + "&";
        String authSignature = generateAuthSignature(baseInfo, compositeKey);
        oauth.put("oauth_signature", authSignature);

        String authHeader = buildAuthHeader(oauth);
        return makeGetRequest(url, authHeader);
    }

    /**
     * Make a GET request to the specified URL with the provided authorization header.
     *
     * @param url     The URL to make the request to.
     * @param header  The OAuth authorization header.
     * @return The response of the request.
     */
    private OneRosterResponse makeGetRequest(String url, String header) {
        int retries = 0;
        while (retries < MAX_RETRIES) {
            try {
                URL theUrl = new URL(url);
                HttpsURLConnection connection = (HttpsURLConnection) theUrl.openConnection();
                connection.setRequestMethod("GET");
                connection.setRequestProperty("Authorization", header);

                int responseCode = connection.getResponseCode();
                Map<String, String> headers = connection.getHeaderFields().entrySet().stream()
                        .filter(e -> e.getKey() != null)
                        .collect(Collectors.toMap(Map.Entry::getKey, e -> String.join(", ", e.getValue())));

                BufferedReader in = new BufferedReader(new InputStreamReader(responseCode == 200 ? connection.getInputStream() : connection.getErrorStream()));
                StringBuilder response = new StringBuilder();
                String inputLine;

                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();

                return new OneRosterResponse(responseCode, response.toString(), headers);
            } catch (IOException e) {
                retries++;
                try {
                    int backoffTime = (int) (Math.pow(2, retries) + ThreadLocalRandom.current().nextInt(1000));
                    Thread.sleep(backoffTime);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }
        return new OneRosterResponse(0, "An error occurred, check your url or network connection");
    }

    /**
     * Handle rate limiting and server errors with exponential backoff and jitter.
     *
     * @param statusCode The status code received from the server.
     */
    private void handleRateLimitingAndServerErrors(int statusCode) {
        int retries = 0;
        while (retries < MAX_RETRIES) {
            try {
                int backoffTime = (int) (Math.pow(2, retries) + ThreadLocalRandom.current().nextInt(1000));
                Thread.sleep(backoffTime);
                retries++;
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
        }
        throw new RuntimeException("Failed after retries due to error: " + statusCode);
    }

    /**
     * Generate a nonce of the specified length.
     *
     * @param len The length of the nonce.
     * @return The generated nonce.
     */
    private String generateNonce(int len) {
        SecureRandom rnd = new SecureRandom();
        return rnd.ints(len, 0, 62)
                .mapToObj(i -> "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".charAt(i))
                .collect(StringBuilder::new, StringBuilder::append, StringBuilder::append)
                .toString();
    }

    /**
     * Build the OAuth authorization header.
     *
     * @param oauth The OAuth parameters.
     * @return The OAuth authorization header.
     */
    private String buildAuthHeader(Map<String, String> oauth) {
        return oauth.entrySet().stream()
                .map(entry -> String.format("%s=\"%s\"", entry.getKey(), encodeURL(entry.getValue())))
                .collect(Collectors.joining(", ", "OAuth ", ""));
    }

    /**
     * Generate the OAuth signature.
     *
     * @param baseInfo     The base string to sign.
     * @param compositeKey The composite key used for signing.
     * @return The generated OAuth signature.
     */
    private String generateAuthSignature(String baseInfo, String compositeKey) {
        try {
            Mac sha256 = Mac.getInstance("HmacSHA256");
            sha256.init(new SecretKeySpec(compositeKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] hash = sha256.doFinal(baseInfo.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to generate HMAC signature", e);
        }
    }

    /**
     * Build the base string for the OAuth signature.
     *
     * @param baseUrl   The base URL.
     * @param method    The HTTP method.
     * @param allParams The URL and OAuth parameters.
     * @return The base string for the OAuth signature.
     */
    private String buildBaseString(String baseUrl, String method, Map<String, String> allParams) {
        String params = allParams.entrySet().stream()
                .map(entry -> String.format("%s=%s", entry.getKey(), encodeURL(entry.getValue())))
                .collect(Collectors.joining("&"));
        return String.format("%s&%s&%s", method, encodeURL(baseUrl), encodeURL(params));
    }

    /**
     * URL encode the given string.
     *
     * @param str The string to encode.
     * @return The URL encoded string.
     */
    private String encodeURL(String str) {
        return URLEncoder.encode(str, StandardCharsets.UTF_8).replace("+", "%20");
    }

    /**
     * Combine and sort all parameters.
     *
     * @param oauth     The OAuth parameters.
     * @param urlParams The URL parameters.
     * @return A sorted map of all parameters.
     */
    private Map<String, String> sortAllParams(Map<String, String> oauth, Map<String, String> urlParams) {
        Map<String, String> result = new TreeMap<>(oauth);
        result.putAll(urlParams);
        return result;
    }

    /**
     * Convert URL query parameters to a map.
     *
     * @param urlPiece The URL query string.
     * @return A map of URL query parameters.
     */
    private Map<String, String> paramsToMap(String urlPiece) {
        return Arrays.stream(urlPiece.split("&"))
                .map(param -> param.split("="))
                .collect(Collectors.toMap(
                        split -> URLDecoder.decode(split[0], StandardCharsets.UTF_8),
                        split -> split.length > 1 ? URLDecoder.decode(split[1], StandardCharsets.UTF_8) : ""
                ));
    }

    /**
     * Parse the response from the API.
     * 
     * @param response The response string from the API.
     * @return A list of parsed records.
     */
    private List<Map<String, Object>> parseResponse(String response) {
        // Implement parsing logic based on the specific response format
        return Collections.emptyList();
    }
}
