<?php

	require_once 'GOAuth2.php';

	/**
	 * OAuth2.0-compliant client.
	 * @package GOAuth2
	 */
	class GOAuth2Client {

		// Unique ID to identify the client to the service provider.
		protected $client_id;

		// The private secret known only to the client and the service provider.
		protected $client_secret;

		// The URI of the service provider's authorization endpoint.
		protected $authorization_uri;

		// The URI of the service provider's token endpoint.
		protected $token_uri;


		/**
		 * Class constructor.
		 * @param 	String			$client_id
		 * @param 	String			$client_secret
		 * @param	String			$authorization_uri
		 * @param	String			$token_uri
		 * @return	GOAuth2Client
		 */
		public function __construct($client_id, $client_secret, $authorization_uri, $token_uri) {
			$this->client_id 			= $client_id;
			$this->client_secret 		= $client_secret;
			$this->authorization_uri	= $authorization_uri;
			$this->token_uri			= $token_uri;
		}


		/**
		 * Get a token using the credentials of the resource owner directly.
		 *
		 * @param String	$username	The resource owner's username.
		 * @param String	$password	The resource owner's password.
		 * @param String	$scope		Optional. A space-delimited list
		 * 								describing the scope of the token
		 * 								request.
		 */
		public function getTokenByResourceOwnerCredentials($username, $password, $scope = null) {
			$params = array(
				'grant_type' 	=> GOAuth2::GRANT_TYPE_PASSWORD,
				'client_id'	 	=> $this->client_id,
				'client_secret'	=> $this->client_secret,
				'username'		=> $username,
				'password'		=> $password
			);

			// Add the scope parameter if non-empty.
			if(!empty($scope)) {
				$params['scope'] = $scope;
			}

			// Construct and make the token request.
			$token_request = new GOAuthHttpRequest($this->token_uri, 'POST', $params, $expect_json = true);

			// Make the token request.
			return $this->makeTokenRequest($token_request);
		}


		/**
		 * Get a token using client credentials only.
		 *
		 * @param	String	$scope	Optional. A space-delimited list describing the
		 * 							scope of the token request.
		 * @return	GoAuth2AccessToken
		 */
		public function getTokenByClientCredentials($scope = null) {

			// Set parameters required for the token request.
			$params = array(
				'grant_type' 	=> GOAuth2::GRANT_TYPE_CLIENT_CREDENTIALS,
				'client_id'		=> $this->client_id,
				'client_secret'	=> $this->client_secret
			);

			// Add the scope parameter if non-empty.
			if(!empty($scope)) {
				$params['scope'] = $scope;
			}

			// Construct and make the token request.
			$token_request = new GOAuthHttpRequest($this->token_uri, 'POST', $params, $expect_json = true);

			// Make the token request.
			return $this->makeTokenRequest($token_request);
		}


		/**
		 * Refresh a held access token.
		 *
		 * @param GOAuth2AccessToken	$token	The held token.
		 * @param String				$scope	Optional. A space-delimited list describing
		 * 										the scope of the token request.
		 */
		public function refreshAccessToken(GOAuth2AccessToken $token, $scope = null) {

			// Set parameters required for the refresh request.
			$params = array(
				'grant_type'	=> GOAuth2::GRANT_TYPE_REFRESH_TOKEN,
				'refresh_token'	=> $token->refresh_token,
				'client_id'		=> $this->client_id,
				'client_secret'	=> $this->client_secret
			);

			// Add the scope parameter if non-empty.
			if(!empty($scope)) {
				$params['scope'] = $scope;
			}

			// Construct and make the refresh request.
			$refresh_request = new GOAuthHttpRequest($this->token_uri, 'POST', $params, $expect_json = true);

			// Make the token request.
			return $this->makeTokenRequest($refresh_request);
		}


		/**
		 * Make a request for a token as specified by the request parameter.
		 *
		 * @param 	GOAuthHttpRequest $request
		 * @throws	GOAuth2TokenException
		 * @return	GOAuth2AccessToken
		 */
		private function makeTokenRequest(GOAuthHttpRequest $request) {

			// Make the request and get the JSON response.
			$json_response = $this->sendRequest($request);

			// If an error was returned, throw an exception.
			if(isset($json_response->error)) {
				$error				= $json_response->error;
				$error_description 	= isset($json_response->error_description) ? $json_response->error_description : null;
				$error_uri 			= isset($json_response->error_uri) ? $json_response->error_uri : null;
				throw new GOAuth2TokenRequestException($error, $error_description, $error_uri);
			}

			// Return a new access token object.
			return new GOAuth2AccessToken(
				$json_response->access_token,
				$json_response->token_type,
				isset($json_response->expires_in) ? $json_response->expires_in : null,
				isset($json_response->refresh_token) ? $json_response->refresh_token : null,
				isset($json_response->scope) ? $json_response->scope : null,
				isset($json_response->secret) ? $json_response->secret : null
			);
		}

		/**
		 * Make an HTTP request to an API endpoint, either via a GET or POST.
		 * If an access token is passed, the request is formatted to use the
		 * token's specified method of authentication - for example, if a MAC
		 * type token is passed, the Authorization header of the request will
		 * be set as needed.
		 *
		 */
		public function call(GOAuthHttpRequest $request, GOAuth2AccessToken $token = null) {

			// If a token was specified, sign the request as appropriate.
			if($token) {
				switch($token->token_type) {
					case GOAuth2::TOKEN_TYPE_BEARER:
						$this->addBearerTokenToRequest($request, $token);
						break;
					case GOAuth2::TOKEN_TYPE_MAC:
						$this->addMACTokenToRequest($request, $token);
						break;
					default:
						throw new GOAuth2Exception('');
				}
			}

			return $this->sendRequest($request);
		}

		private function addMACTokenToRequest(GOAuthHttpRequest $request, GOAuth2AccessToken $token) {

			// @todo: This function!
			return $request;
			// Generate timestamp and nonce and add to params
			$timestamp 	= time();
			$nonce		= uniqid();

			// Normalise request. First break the URI into its component parts.
			$parsed_uri 			= parse_url($request->uri);
			$parsed_uri['scheme']	= isset($parsed_uri['scheme']) ? strtolower($parsed_uri['scheme']) : 'http';
			$parsed_uri['port']		= isset($parsed_uri['port']) ? $parsed_uri['port'] : (($parsed_uri['scheme'] == 'https') ? 443 : 80);

			$request_parts 			= array();
			$request_parts[] 		= $token->access_token;
			$request_parts[] 		= $timestamp;
			$request_parts[] 		= $nonce;
			$request_parts[] 		= ''; // The 'body hash' - not currently using it.
			$request_parts[] 		= strtoupper($request->method);
			$request_parts[]		= strtolower($parsed_uri['host']);
			$request_parts[]		= $parsed_uri['port'];
			$request_parts[]		= $parsed_uri['path'];
			$request_parts[]		= $parsed_uri['query'];


			// Sign using HMAC and base64 encode
			// hash_hmac($algo, $data, $key)

			// Add token, timestamp, nonce and signature to auth header

			return $request;
		}

		/**
		 * Add a simple Bearer access token to the request.
		 *
		 * @param 	GOAuthHttpRequest $request
		 * @param 	GOAuth2AccessToken $token
		 * @return	GOAuthHttpRequest
		 */
		private function addBearerTokenToRequest(GOAuthHttpRequest $request, GOAuth2AccessToken $token) {
			$request->authorization_header = "BEARER {$token->access_token}";
			return $request;
		}

		/**
		 * Make a HTTP request.
		 *
		 * @param	GOAuthHttpRequest	$request
		 * @throws 	GOAuth2Exception
		 * @return	GOAuthHttpResponse
		 */
		public function sendRequest(GOAuthHttpRequest $request) {

			// Set the request headers
			$headers = array();

			// Add the authorization header if set
			if(!empty($request->authorization_header)) {
				$headers[] = 'Authorization: ' . $request->authorization_header;
				$request->authorization_header = null;
			}

			// Initialise the cURL handler and set transfer options.
			$ch = curl_init($request->uri);
			curl_setopt_array($ch, array(
				CURLOPT_POST 			=> ($request->method == 'POST') ? 1 : 0,
				CURLOPT_POSTFIELDS		=> $request->params,
				CURLOPT_RETURNTRANSFER 	=> 1,
				CURLOPT_HTTPHEADER		=> $headers
			));

			// Send the actual request.
			$curl_response = curl_exec($ch);

			// Check that the URI was reachable.
			if ($curl_response === false) {
				curl_close($ch);
				throw new GOAuth2Exception('cURL error');
			}

			// Close the cURL handler.
			curl_close($ch);

			// If the request was expecting a JSON response, be nice and decode.
			if($request->expect_json) {
				return json_decode($curl_response);
			}

			// Return the response.
			return $curl_response;
		}
	}