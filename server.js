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
async function getResourceSet(accessToken) {
  try {
    const response = await axios.get(
      `${keycloakConfig['auth-server-url']}/realms/${keycloakConfig.realm}/authz/protection/resource_set?uri=/settings`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    );

    return response.data;
  } catch (error) {
    console.error('Error during resource set request:', error.message);
    throw error;
  }
}

app.post('/settings', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).send('Bad Request: Missing required parameters.');
    }

    const response = await axios.post(
      `${keycloakConfig['auth-server-url']}/realms/${keycloakConfig.realm}/protocol/openid-connect/token`,
      `grant_type=password&client_id=${keycloakConfig.resource}&client_secret=${keycloakConfig.credentials.secret}&username=${username}&password=${password}`,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      }
    );

    const accessToken = response.data.access_token;

    // Make a GET request to the resource_set endpoint
    const resourceSet = await getResourceSet(accessToken);

    // Log resource set for debugging
    console.log('Resource Set:', resourceSet);

    // Check if the resourceSet is not null and has at least one element
    if (Array.isArray(resourceSet) && resourceSet.length > 0) {
      // Extract the first value from the resourceSet as the id
      const id = resourceSet[0];

      // Make a POST request to the Keycloak token endpoint with additional information
      const umaTicketResponse = await axios.post(
        `${keycloakConfig['auth-server-url']}/realms/${keycloakConfig.realm}/protocol/openid-connect/token`,
        `grant_type=urn:ietf:params:oauth:grant-type:uma-ticket&client_id=${keycloakConfig.resource}&client_secret=${keycloakConfig.credentials.secret}&audience=${keycloakConfig.resource}&permission=${id}&response_mode=permissions`,
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Authorization: `Bearer ${accessToken}`,
          },
        }
      );

      // Log umaTicketResponse for debugging
      console.log('UMA Ticket Response:', umaTicketResponse.data);

      // Return umaTicketResponse as a JSON response
      res.json(umaTicketResponse.data);
    } else {
      // If resourceSet is null or empty, return an appropriate response
      res.status(404).send('Resource Set not found or empty');
    }
  } catch (error) {
    console.error('Error:', error.message);

    // Check for a 403 status in the error response
    if (error.response && error.response.status === 403) {
      // Send the entire error.response.data as the response
      res.status(403).json(error.response.data);
    } else {
      // Handle other errors with a generic 500 status and message
      res.status(500).send(error.message);
    }
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
      console.log(keycloakResponse.data.active);
      const roles = keycloakResponse.data.realm_access.roles;

      if (roles.includes('Engineer')) {
        // The user has the required role
        res.send('This is a secure route to /settings for  engineers.');
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
      res.status(500).send(error.message);
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
