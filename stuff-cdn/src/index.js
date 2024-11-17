export default {
	async fetch(request, env) {
	  const url = new URL(request.url);
	  const path = url.pathname.substring(1); // Haal het pad van het bestand uit de URL
	  const method = request.method;
  
	  // Afhandeling van preflight OPTIONS-verzoeken (CORS)
	  if (method === 'OPTIONS') {
		return handleOptionsRequest();
	  }
  
	  // Hoofdpagina geeft altijd een foutmelding
	  if (!path) {
		return addCorsHeaders(new Response('Error: No file specified', { status: 400 }));
	  }
  
	  switch (true) {
		case path.startsWith('list') && method === 'GET':
		  return addCorsHeaders(await handleListRequest(request, env));
		  
		case path.startsWith('upload') && method === 'POST':
		  return addCorsHeaders(await handleUploadRequest(request, env, path.substring(7))); // Haal bestandsnaam na 'upload/'
		  
		case path.startsWith('delete') && method === 'DELETE':
		  return addCorsHeaders(await handleDeleteRequest(request, env, path.substring(7))); // Haal bestandsnaam na 'delete/'
		  
		default:
		  if (method === 'GET') {
			// Probeer het bestand op te halen als het pad geen speciale route is
			return addCorsHeaders(await handleGetFileRequest(path, env));
		  }
	  }
  
	  return addCorsHeaders(new Response('Method Not Allowed', { status: 405 }));
	},
  };
  
  // Functie om CORS-headers toe te voegen aan elke response
  function addCorsHeaders(response) {
	response.headers.set('Access-Control-Allow-Origin', '*'); // Of specificeer een domein i.p.v. '*'
	response.headers.set('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
	response.headers.set('Access-Control-Allow-Headers', 'x-api-key, Content-Type');
	return response;
  }
  
  // Verwerk OPTIONS-verzoeken voor preflight CORS
  function handleOptionsRequest() {
	return new Response(null, {
	  headers: {
		'Access-Control-Allow-Origin': '*',
		'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
		'Access-Control-Allow-Headers': 'x-api-key, Content-Type',
	  },
	});
  }
  
  // Verwerk GET-verzoek voor lijst met bestanden (alleen met API-sleutel)
  async function handleListRequest(request, env) {
	const apiKey = request.headers.get('x-api-key');
	if (apiKey !== env.API_KEY) {
	  return new Response('Unauthorized', { status: 401 });
	}
  
	// Lijst alle bestanden in de bucket
	const listResult = await env.STUFF_BUCKET.list();
	const files = listResult.objects.map((object) => object.key);
	return new Response(JSON.stringify(files), { headers: { 'Content-Type': 'application/json' } });
  }
  
  // Verwerk POST-verzoek voor uploaden van bestand (alleen met API-sleutel)
  async function handleUploadRequest(request, env, filename) {
	const apiKey = request.headers.get('x-api-key');
	if (apiKey !== env.API_KEY) {
	  return new Response('Unauthorized', { status: 401 });
	}
  
	if (!filename) {
	  return new Response('File path is required', { status: 400 });
	}
  
	// Lees de body van het verzoek als een stream
	const body = await request.arrayBuffer();
  
	// Upload het bestand naar de R2-bucket
	await env.STUFF_BUCKET.put(filename, body);
  
	return new Response(`File ${filename} uploaded successfully`, { status: 200 });
  }
  
  // Verwerk DELETE-verzoek voor verwijderen van bestand (alleen met API-sleutel)
  async function handleDeleteRequest(request, env, filename) {
	const apiKey = request.headers.get('x-api-key');
	if (apiKey !== env.API_KEY) {
	  return new Response('Unauthorized', { status: 401 });
	}
  
	if (!filename) {
	  return new Response('File path is required', { status: 400 });
	}
  
	// Verwijder het bestand uit de R2-bucket
	await env.STUFF_BUCKET.delete(filename);
  
	return new Response(`File ${filename} deleted successfully`, { status: 200 });
  }
  
  // Verwerk GET-verzoek voor ophalen van specifiek bestand zonder authenticatie
  async function handleGetFileRequest(path, env) {
	// Haal een specifiek bestand op uit de bucket
	const object = await env.STUFF_BUCKET.get(path);
	
	if (!object) {
	  // Gooi een fout als het bestand niet bestaat
	  return new Response(`Error: File '${path}' not found`, { status: 404 });
	}
  
	return new Response(object.body, {
	  headers: { 'Content-Type': object.httpMetadata.contentType || 'application/octet-stream' },
	});
  }