<?php

	include '../GOAuth2Client.php';

	define('CLIENT_ID', 				'46606f8aa441ae85e65a94b7e85df9b5');
	define('CLIENT_SECRET', 			'bcf62025dbbc5bc22b1dfdf95c455fe3');
	define('AUTHORIZATION_ENDPOINT',	'http://' . $_SERVER['HTTP_HOST'] . dirname($_SERVER['REQUEST_URI']) . '/endpoints/authorization.php');
	define('TOKEN_ENDPOINT',			'http://' . $_SERVER['HTTP_HOST'] . dirname($_SERVER['REQUEST_URI']) . '/endpoints/token.php');
	define('API_ENDPOINT',				'http://' . $_SERVER['HTTP_HOST'] . dirname($_SERVER['REQUEST_URI']) . '/endpoints/api.php');

	// Make sure that our client exists in our Mongo DB
	$m = new Mongo(); $m->goauth2->clients->save(array("client_id" => CLIENT_ID, "client_secret" => CLIENT_SECRET));

	// Instantiate the client.
	$client = new GOAuth2Client(CLIENT_ID, CLIENT_SECRET, AUTHORIZATION_ENDPOINT, TOKEN_ENDPOINT, '', GOAuth2::SERVER_AUTH_TYPE_HTTP_BASIC);

	// Obtain an access token using our client credentials.
	try {
		$token = $client->getTokenByClientCredentials();
	} catch(GOAuth2Exception $e) {
		echo "Couldn't retrieve an access token from the token endpoint! ({$e->getDescription()})";
		exit;
	}

	// Set the client's active token to the newly retrieved token.
	$client->setToken($token);

	// Build a request to our example API endpoint.
	try {

		$api_params = array('method' => 'ping');
		$request = new GOAuth2HttpRequest(API_ENDPOINT, $method = 'POST', $api_params);

		// Make the request using the call() method. Our HTTP request to the API endpoint
		// will automatically be signed using the type of token returned.
		$json_response = $client->call($request);

	} catch(GOAuth2ConnectionException $e) {
		echo "Couldn't connect to API endpoint! ({$e->getDescription()})";
		exit;
	}

	// Decode the JSON response
	$response_obj = json_decode($json_response);
	echo '<pre>';
	print_r($response_obj);
	echo '</pre>';