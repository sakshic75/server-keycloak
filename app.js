const axios = require('axios');

const keycloakBaseUrl = 'http://localhost:8080'; // Replace with your Keycloak server URL
const realm = 'myrealm'; // Replace with your Keycloak realm
const clientId = 'resource-app'; // Replace with your client ID
const userId = '7b2eccef-0356-4852-aae9-1b94630882e4'; // Replace with the user ID you want to test
const resource = 'res:settings'; // Replace with the resource you want to test
const scope = 'settings-view'; // Replace with the scope you want to test

const getKeycloakToken = async () => {
  const tokenUrl = `${keycloakBaseUrl}/realms/${realm}/protocol/openid-connect/token`;
  const response = await axios.post(
    tokenUrl,
    new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: 'resource-app',
      client_secret: 'j689iftdC0iHqUGuK4tQeYrprIYaje05', // Replace with your client secret
    }),
    {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    }
  );
  return response.data.access_token;
};

const evaluateAuthorization = async () => {
  try {
    const accessToken = await getKeycloakToken();
    const evaluateUrl = `${keycloakBaseUrl}/admin/realms/${realm}/clients/${clientId}/evaluation`;

    const response = await axios.post(
      evaluateUrl,
      {
        userId: userId,
        clientId: clientId,
        resources: [resource],
        scopes: [scope],
      },
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
      }
    );

    console.log('Authorization Evaluation Result:', response.data);
  } catch (error) {
    console.error('Error evaluating authorization:', error.response ? error.response.data : error.message);
  }
};

evaluateAuthorization();
