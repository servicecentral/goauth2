<?php

	require_once 'GOAuth2.php';

	/**
	 * OAuth2.0-compliant client.
	 * @package GOAuth2
	 */
	class GOAuth2Client {

		// Unique ID to identify the client to the service provider.
		private $client_id;

		// The private secret known only to the client and the service provider.
		private $client_secret;

		// The URI of the service provider's authorization endpoint.
		private $authorization_uri;

		// The URI of the service provider's token endpoint.
		private $token_uri;


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
				isset($json_response->scope) ? $json_response->scope : null
			);
		}


		/**
		 * Make a HTTP request.
		 *
		 * @param	GOAuthHttpRequest	$request
		 * @throws 	GOAuth2Exception
		 * @return	GOAuthHttpResponse
		 */
		public function sendRequest(GOAuthHttpRequest $request) {
			// Initialise the cURL handler and set transfer options.
			$ch = curl_init($request->uri);
			curl_setopt_array($ch, array(
				CURLOPT_POST 			=> ($request->method == 'POST') ? 1 : 0,
				CURLOPT_POSTFIELDS		=> $request->params,
				CURLOPT_RETURNTRANSFER 	=> 1
			));

			// Send the actual request.
			$curl_response = curl_exec($ch);

			// Check that the URI was reachable.
			if ($curl_response === false) {
				curl_close($ch);
				throw new GOAuth2Exception();
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