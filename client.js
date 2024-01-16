const keycloakConfig = {
    realm: 'your-realm',
    "auth-server-url": "http://localhost:8080/auth",
    "resource": "your-client-id",
    "ssl-required": "external",
    "bearer-only": true,
    "public-client": true
  };
  
  // Assuming the Keycloak object is already configured
  const keycloak = new Keycloak({}, 'keycloak-config.json');
  
  // Authenticate the user
  keycloak.init({ onLoad: 'login-required' })
    .then(() => {
      // Access token is available in keycloak.token
      const accessToken = keycloak.token;
  
      // Include the access token in the Authorization header
      const headers = {
        Authorization: `Bearer ${accessToken}`
      };
  
      // Make a request to a protected resource (e.g., '/secure/resource')
      fetch('http://localhost:3001/secure/resource', { headers })
        .then(response => {
          if (response.ok) {
            return response.text();
          } else {
            throw new Error('Access denied.');
          }
        })
        .then(data => console.log(data))
        .catch(error => console.error(error));
    })
    .catch(error => console.error(error));
  