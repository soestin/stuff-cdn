export default {
	async fetch(request, env) {
	  const url = new URL(request.url);
	  const path = url.pathname.substring(1); // Get path from URL
	  const method = request.method;
  
	  // Handle preflight OPTIONS requests (CORS)
	  if (method === 'OPTIONS') {
		return handleOptionsRequest();
	  }
  
	  // Homepage always returns error message
	  if (!path) {
		return addCorsHeaders(new Response('Error: No file specified', { status: 400 }));
	  }
  
	  switch (true) {
		case path.startsWith('list') && method === 'GET':
		  return addCorsHeaders(await handleListRequest(request, env));
		  
		case path.startsWith('upload') && method === 'POST':
		  return addCorsHeaders(await handleUploadRequest(request, env, path.substring(7))); // Get filename after 'upload/'
		  
		case path.startsWith('delete') && method === 'DELETE':
		  return addCorsHeaders(await handleDeleteRequest(request, env, path.substring(7))); // Get filename after 'delete/'
		  
		default:
		  if (method === 'GET') {
			// Try to retrieve file if path is not a special route
			return addCorsHeaders(await handleGetFileRequest(path, env));
		  }
	  }
  
	  return addCorsHeaders(new Response('Method Not Allowed', { status: 405 }));
	},
  };
  
  // Function to add CORS headers to every response
  function addCorsHeaders(response) {
	response.headers.set('Access-Control-Allow-Origin', '*'); // Or specify a domain instead of '*'
	response.headers.set('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
	response.headers.set('Access-Control-Allow-Headers', 'x-api-key, Content-Type');
	return response;
  }
  
  // Handle OPTIONS requests for preflight CORS
  function handleOptionsRequest() {
	return new Response(null, {
	  headers: {
		'Access-Control-Allow-Origin': '*',
		'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
		'Access-Control-Allow-Headers': 'x-api-key, Content-Type',
	  },
	});
  }
  
  // Handle GET request for list of files (only with API key)
  async function handleListRequest(request, env) {
	const apiKey = request.headers.get('x-api-key');
	if (apiKey !== env.API_KEY) {
	  return new Response('Unauthorized', { status: 401 });
	}
  
	// List all files in the bucket
	const listResult = await env.STUFF_BUCKET.list();
	const files = listResult.objects.map((object) => object.key);
	return new Response(JSON.stringify(files), { headers: { 'Content-Type': 'application/json' } });
  }
  
  // Handle POST request for uploading file (only with API key)
  async function handleUploadRequest(request, env, filename) {
	const apiKey = request.headers.get('x-api-key');
	if (apiKey !== env.API_KEY) {
	  return new Response('Unauthorized', { status: 401 });
	}
  
	if (!filename) {
	  return new Response('File path is required', { status: 400 });
	}
  
	// Read the body of the request as a stream
	const body = await request.arrayBuffer();
  
	// Upload the file to the R2 bucket
	await env.STUFF_BUCKET.put(filename, body);
  
	return new Response(`File ${filename} uploaded successfully`, { status: 200 });
  }
  
  // Handle DELETE request for deleting file (only with API key)
  async function handleDeleteRequest(request, env, filename) {
	const apiKey = request.headers.get('x-api-key');
	if (apiKey !== env.API_KEY) {
	  return new Response('Unauthorized', { status: 401 });
	}
  
	if (!filename) {
	  return new Response('File path is required', { status: 400 });
	}
  
	// Delete the file from the R2 bucket
	await env.STUFF_BUCKET.delete(filename);
  
	return new Response(`File ${filename} deleted successfully`, { status: 200 });
  }
  
  // Handle GET request for retrieving specific file without authentication
  async function handleGetFileRequest(path, env) {
	// Retrieve a specific file from the bucket
	const object = await env.STUFF_BUCKET.get(path);
	
	if (!object) {
	  // Throw error if the file does not exist
	  return new Response(`Error: File '${path}' not found`, { status: 404 });
	}
  
	return new Response(object.body, {
	  headers: { 'Content-Type': object.httpMetadata.contentType || 'application/octet-stream' },
	});
  }

