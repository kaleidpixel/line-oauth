<?php
/**
 * LINE OAuth.
 *
 * @package   KaleidPixel
 * @author    KUCKLU <hello@kuck1u.me>
 * @copyright 2019 Kaleid Pixel
 * @licenses  MIT License.
 * @version   0.0.1
 */

namespace KaleidPixel\OAuth;

/**
 * Class LineOAuth
 *
 * @package KaleidPixel\OAuth
 */
class LineOAuth
{
    const API_VERSION = '2.1';

    /**
     * @var string
     */
    public $clientId;

    /**
     * @var string
     */
    public $clientSecret;

    /**
     * @var string A unique alphanumeric string used to prevent cross-site request forgery.
     */
    public $state;

    function __construct($clientId = '', $clientSecret = '', $state = '')
    {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->generateState($state);
    }

    /**
     * @param string $state
     */
    public function generateState($state = '')
    {
        $this->state = empty($state) ? bin2hex(openssl_random_pseudo_bytes(16)) : $state;
    }

    /**
     * Return the OAuth URL
     *
     * @param string $redirectUri
     *
     * @return string
     */
    public function oauthUrl($redirectUri = '')
    {
        $query = [
            'response_type' => 'code',
            'client_id' => filter_var($this->clientId, FILTER_SANITIZE_STRING),
            'redirect_uri' => self::sanitizeUrl($redirectUri),
            'state' => $this->state,
            'scope' => 'profile',
        ];

        return 'https://access.line.me/oauth2/v' . self::API_VERSION . '/authorize?' . http_build_query($query);
    }

    /**
     * @param string $code
     * @param string $redirectUri
     * @return |null
     */
    public function getToken($code = '', $redirectUri = '')
    {
        $token = null;
        $query = [
            'grant_type' => 'authorization_code',
            'code' => filter_var($code, FILTER_SANITIZE_STRING),
            'redirect_uri' => self::sanitizeUrl($redirectUri),
            'client_id' => filter_var($this->clientId, FILTER_SANITIZE_STRING),
            'client_secret' => filter_var($this->clientSecret, FILTER_SANITIZE_STRING),
        ];
        $response = self::getContent('https://api.line.me/oauth2/v' . self::API_VERSION . '/token', $query, 'POST');

        if (isset($response['content']) && isset($response['http_code']) && $response['http_code'] === 200) {
            $content = json_decode($response['content']);
            $token = $content->access_token;
        }

        return $token;
    }

    /**
     * @param string $token
     * @return array|mixed
     */
    public function getUser($token = '')
    {
        $user = [];
        $token = filter_var($token, FILTER_SANITIZE_STRING);
        $response = self::getContent('https://api.line.me/v2/profile', [], 'GET', ["Authorization: Bearer {$token}"]);

        if (isset($response['content']) && isset($response['http_code']) && $response['http_code'] === 200) {
            $user = json_decode($response['content']);
        }

        return $user;
    }

    /**
     * @param string $url
     * @return mixed|string
     */
    private static function sanitizeUrl($url = '')
    {
        $url = strip_tags(str_replace(array('"', "'", '`', '´', '¨'), '', trim($url)));
        $url = filter_var($url, FILTER_SANITIZE_URL);

        return $url;
    }

    /**
     * @param string $url
     * @param array $header
     * @param string $method
     * @param array $data
     *
     * @return array
     */
    private static function getContent($url = '', $data = [], $method = 'GET', $header = [])
    {
        $result = array();
        $url = strip_tags(str_replace(array('"', "'", '`', '´', '¨'), '', trim($url)));
        $url = filter_var($url, FILTER_SANITIZE_URL);
        $httpheader = array('Content-Type: application/x-www-form-urlencoded');

        if (is_array($header) && !empty($header)) {
            $httpheader = array_merge($httpheader, $header);
        }

        if (!empty($url)) {
            $ch = curl_init();

            if (mb_strtoupper($method) === 'POST') {
                curl_setopt($ch, CURLOPT_POST, true);
                curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
            }

            curl_setopt($ch, CURLOPT_HTTPHEADER, $httpheader);
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_FORBID_REUSE, true);
            curl_setopt($ch, CURLOPT_FRESH_CONNECT, true);

            $result['content'] = curl_exec($ch);
            $result['http_code'] = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $result['url'] = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);

            curl_close($ch);
        }

        return $result;
    }

    /**
     * @param $input
     *
     * @return array|mixed|string
     */
    private static function urlencode($input)
    {
        $result = '';

        if (is_object($input)) {
            $input = (array)$input;
        }

        if (is_array($input)) {
            $result = array_map([__CLASS__, 'urlencode'], $input);

            foreach ($input as $k => $v) {
                if (is_object($v)) {
                    $v = (array)$v;
                }

                if (is_array($v)) {
                    $input[$k] = array_map([__CLASS__, 'urlencode'], $v);
                } elseif (is_scalar($input)) {
                    $input[$k] = rawurlencode($v);
                }
            }
        } elseif (is_scalar($input)) {
            $result = rawurlencode($input);
        }

        return $result;
    }
}
