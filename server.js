const express = require('express');
const session = require('express-session');
const Keycloak = require('keycloak-connect');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3001;

// Load Keycloak configuration from keycloak-config.json
const keycloakConfig = JSON.parse(fs.readFileSync('keycloak-config.json', 'utf8'));

// Initialize session middleware
app.use(
  session({
    secret: 'mjfhjkfhekgh',
    resave: false,
    saveUninitialized: true,
  })
);
app.use(express.json());

// Initialize Keycloak
const keycloak = new Keycloak({
},'keycloak-config.json');


// Function to introspect the token using Keycloak Introspection endpoint
async function introspectToken(accessToken) {
  try {
    const introspectionResponse = await axios.post(
      `${keycloakConfig['auth-server-url']}/realms/${keycloakConfig.realm}/protocol/openid-connect/token/introspect`,
      `token=${accessToken}&client_id=${keycloakConfig.resource}&client_secret=${keycloakConfig.credentials.secret}`,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      }
    );

    return introspectionResponse.data;
  } catch (error) {
    console.error('Error during token introspection:', error.message);
    throw error;
  }
}

// Example route without using keycloak.protect middleware
app.get('/settings', keycloak.protect(), async (req, res) => {
  try {
    const authorizationHeader = req.headers['authorization'];

    if (!authorizationHeader) {
      return res.status(401).send('Unauthorized');
    }

    // Extract the access token from the Authorization header
    const accessToken = authorizationHeader.split(' ')[1];

    // Introspect the token to check if it is active and authorized
    const introspectionResult = await introspectToken(accessToken);

    // Log introspection result for debugging
    console.log('Introspection Result:', introspectionResult);

    // Check if the token is active
    if (introspectionResult.active) {
      console.log('Realm Roles:', introspectionResult.realm_access.roles);
      console.log('Resource Access:', introspectionResult.resource_access);
      console.log('Scopes:', introspectionResult.scope);

      const decodedToken = jwt.decode(accessToken, { complete: true });
      if (decodedToken && decodedToken.realm_access && decodedToken.realm_access.roles.includes('Engineer')) {
        const resourceAccess = decodedToken.resource_access;
        if (
          resourceAccess &&
          resourceAccess['res:settings'] &&
          resourceAccess['res:settings'].roles.includes('Engineer') &&
          resourceAccess['res:settings'].scopes.includes('settings-view')
        ) {
          res.send('This is a secure route for engineers with "view" scope for res:settings.');
        } else {
          res.status(403).send('Forbidden: Insufficient scope');
        }
      } else {
        res.status(403).send('Forbidden: Insufficient role');
      }
    } else {
      res.status(401).send('Unauthorized: Token is not active');
    }
  } catch (error) {
    console.error('Error:', error.message);
    res.status(500).send(error.message);
  }
});

// /custom-login route
app.post('/custom-login', async (req, res) => {
  try {
    const { username, password, grant_type } = req.body;

    console.log('Received parameters:', { username, password, grant_type });

    if (!username || !password || !grant_type) {
      return res.status(400).send('Bad Request: Missing required parameters.');
    }

    const response = await axios.post(
      `${keycloakConfig['auth-server-url']}/realms/${keycloakConfig.realm}/protocol/openid-connect/token`,
      `grant_type=${grant_type}&client_id=${keycloakConfig.resource}&client_secret=${keycloakConfig.credentials.secret}&username=${username}&password=${password}`,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      }
    );

    // Extract the access token from the response
    const accessToken = response.data.access_token;

    // Use the access token to make a request to the Keycloak introspection endpoint
    const keycloakResponse = await axios.post(
      `${keycloakConfig['auth-server-url']}/realms/${keycloakConfig.realm}/protocol/openid-connect/token/introspect`,
      `token=${accessToken}&client_id=${keycloakConfig.resource}&client_secret=${keycloakConfig.credentials.secret}`,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      }
    );

    // Check if the token is valid and authorized
    if (keycloakResponse.data.active) {
      const roles = keycloakResponse.data.realm_access.roles;

      if (roles.includes('Engineer')) {
        // The user has the required role
        res.send('This is a secure route for engineers.');
      } else {
        // The user does not have the required role
        res.status(403).send('Forbidden: User has no Engineer role');
      }
    } else {
      // The token is invalid or unauthorized
      res.status(401).send('User is Unauthorized');
    }
  } catch (error) {
    // Handle errors
    if (error.response && error.response.status) {
      // If the error has an HTTP status code, send that status code in the response
      res.status(error.response.status).send(error.message);
    } else {
      // If the error does not have an HTTP status code, send a generic 500 error
      console.error('Error:', error.message);
      res.status(500).send('Internal Server Error');
    }
  }
});

app.get('/secure', async (req, res) => {
  try {
    // Extract the access token from the Authorization header
    const authorizationHeader = req.headers['authorization'];

    if (!authorizationHeader) {
      // No Authorization header found
      return res.status(401).send('Unauthorized');
    }

    // Extract the access token from the Authorization header
    const accessToken = authorizationHeader.split(' ')[1];

    // Use the access token to make a request to the Keycloak introspection endpoint
    const keycloakResponse = await axios.post(
      `${keycloakConfig['auth-server-url']}/realms/${keycloakConfig.realm}/protocol/openid-connect/token/introspect`,
      `token=${accessToken}&client_id=${keycloakConfig.resource}&client_secret=${keycloakConfig.credentials.secret}`,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      }
    );

    // Check if the token is valid and authorized
    if (keycloakResponse.data.active) {
      const roles = keycloakResponse.data.realm_access.roles;

      if (roles.includes('Engineer')) {
        // The user has the required role
        res.send('This is a secure route for engineers.');
      } else {
        // The user does not have the required role
        res.status(403).send('Forbidden: User has no Engineer role');
      }
    } else {
      // The token is invalid or unauthorized
      res.status(401).send('User is Unauthorized');
    }
  } catch (error) {
    // Handle errors
    console.error('Error:', error.message);
    res.status(500).send(error.message);
  }
});


// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
