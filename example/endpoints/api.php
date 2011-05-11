<?php

	include '../../GOAuth2APIEndpoint.php';
	include '../lib/mongo_api_endpoint.php';

	// A short function to send a JSON response.
	function send_json_response($success, $content) {
		@ob_end_clean(); header("Content-Type: application/json");
		echo json_encode(array('success' => $success, 'content' => $content)); exit;
	}

	$api = new MongoAPIEndpoint();

	// Get the authorization header from the request (Apache only - other HTTP servers should reimplement)
	$headers 				= apache_request_headers();
	$authorization_header 	= isset($headers['Authorization']) ? $headers['Authorization'] : '';

	// Get the full request URI, including querystring.
	$request_uri 			= $_SERVER['HTTP_HOST'] . ':' . $_SERVER['SERVER_PORT'] . $_SERVER['REQUEST_URI'];
	$request_method			= $_SERVER['REQUEST_METHOD'];

	/*
	error_log(print_r(array(
		$request_uri,
		$request_method,
		$_REQUEST,
		$authorization_header
	), true));
	*/

	// Attempt to authenticate the request.
	try {
		$api->authenticateRequest($request_uri, $request_method, $_REQUEST, $authorization_header);
	} catch(GOAuth2Exception $e) {
		send_json_response($success = false, $e->getDescription());
	}

	// Authentication, do API processing.
	switch($_POST['method']) {
		case 'ping':
			send_json_response($success = true, $content = true);
		default:
			send_json_response($success = false, $content = 'Unknown method.');
	}