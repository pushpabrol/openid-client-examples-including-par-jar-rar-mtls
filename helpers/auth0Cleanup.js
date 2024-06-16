import dotenv from 'dotenv'
import {  __dirname } from './helpers.js';
import { ManagementClient } from 'auth0';
dotenv.config(`${__dirname}/.env`)
import chalk from 'chalk'; // Node.js file for colorful logs

// Create a new instance of the ManagementClient
const auth0 = new ManagementClient({
    domain: process.env.AUTH0_DOMAIN,
    clientId: process.env.MGMT_CLIENT_ID,
    clientSecret: process.env.MGMT_CLIENT_SECRET,
});

// List all clients with pagination
const getAllClients = async () => {
    try {
      let page = 0;
      let clients = [];
  
      while (true) {
        const result = (await auth0.clients.getAll({
          page: page,
          per_page: 100,
          fields: 'client_id,name,callbacks,app_type',
          include_fields: true // Adjust the number of clients per page as needed
        })).data;
  
        clients = clients.concat(result);
  
        // Break the loop if the number of returned clients is less than the per_page value,
        // indicating that we have retrieved all clients
        if (result.length < 100) {
          break;
        }
  
        page++;
      }
  
      return clients;
    } catch (error) {
      console.error(error);
    }
  };

  const filterClientsByName = (clients, nameFilters) => {
    const filteredClients = clients.filter((client) => {
      for (const filter of nameFilters) {
        if (client.name.toLowerCase().startsWith(filter.toLowerCase())) {
          return true;
        }
      }
      return false;
    });
  
    return filteredClients;
  };
  

  const filterClientsByCallbacks = (clients) => {
    const filteredClients = clients.filter((client) => {
      
        if (typeof client.callbacks === 'undefined') {
          return true;
        }
      
      return false;
    });
  
    return filteredClients;
  };

  const filterResourceServersByIdentifier = (reseourceservers, identifiers) => {
    const filteredRSs = reseourceservers.filter((rs) => {
      for (const identifier of identifiers) {
        if (rs.identifier === identifier) {
          return true;
        }
      }
      return false;
    });
  
    return filteredRSs;
  };

  const getAllResourceServers = async () => {
    try {
      let page = 0;
      let reseourceservers = [];
  
      while (true) {
        const result = (await auth0.resourceServers.getAll({
          page: page,
          per_page: 100,
          fields: 'id,name,identifier',
          include_fields: true // Adjust the number of reseourceservers per page as needed
        })).data;
  
        reseourceservers = reseourceservers.concat(result);
  
        // Break the loop if the number of returned reseourceservers is less than the per_page value,
        // indicating that we have retrieved all clients
        if (result.length < 100) {
          break;
        }
  
        page++;
      }
  
      return reseourceservers;
    } catch (error) {
      console.error(error);
    }
  };

  const printClientNamesAndIds = (clients) => {
    clients.forEach((client) => {
      console.log(chalk.green(`Client Name: ${client.name}`));
      console.log(chalk.green(`Client ID: ${client.client_id}`));
      console.log(chalk.green(`Client Callbacks: ${client.callbacks}`));
      console.log(chalk.green(`Client Type: ${client.app_type}`));
      console.log(chalk.green('-------------------'));
    });
  };

  const printRSDetails = (rss) => {
    rss.forEach((rs) => {
      console.log(chalk.green(`RS Name: ${rs.name}`));
      console.log(chalk.green(`RS ID: ${rs.id}`));
      console.log(chalk.green(`RS Audience: ${rs.identifier}`));
      console.log(chalk.green('-------------------'));
    });
  };

// Delay function to handle rate limiting
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Function to delete clients with rate limiting protection
const deleteClients = async (clients) => {
  try {

    for (const client of clients) {
      await auth0.clients.delete({ client_id: client.client_id });
      console.log(chalk.green(`Deleted client with ID: ${client.client_id}`));

      // Delay between each deletion to handle rate limiting
      await delay(200); // Adjust the delay time as needed
    }
  } catch (error) {
    console.error(error);
  }
};
// Function to delete resource servers with rate limiting protection
const deleteResourceServers = async (rss) => {
    try {
  
      for (const rs of rss) {
        await auth0.resourceServers.delete({ id: rs.id });
        console.log(chalk.green(`Deleted RS with ID: ${rs.id}`));
  
        // Delay between each deletion to handle rate limiting
        await delay(200); // Adjust the delay time as needed
      }
    } catch (error) {
      console.error(error);
    }
  };

// Usage
/**
 * This function assumes that all clients and resource servers have been named using the convention used in the templates in the bootstrap.js file
 * 
 */
var clients = await getAllClients();
console.log(chalk.green("In this Auth0 tenant - Total number of clients ", clients.length));
var reseourceservers = await getAllResourceServers();
console.log(chalk.green("In this Auth0 tenant - Total number of Resource Servers ", reseourceservers.length));
const rsIdentifiers = ["urn:your:api","urn:bank:api:hri","urn:my:api:hri:encrypted_accessToken"];
const clientFilters = ["MTLS_", "Native_Device_FLow_Test-","RWA_CLIENT_","Native_Device_FLow_Test","SPA_Test_Client","PKJWT_CLIENT","JAR_CLIENT","JARPKJWT_CLIENT"];

var filteredClients = filterClientsByName(clients,clientFilters);
//var filteredClients = filterClientsByCallbacks(clients);
if(filteredClients.length > 0)
{
printClientNamesAndIds(filteredClients)
console.log(chalk.green(`Found ${filteredClients.length} clients that would be deleted`));
deleteClients(filteredClients);
} else console.log(chalk.yellow(`No clients with names matching the filters found!!!`))
var filteredRSs = filterResourceServersByIdentifier(reseourceservers,rsIdentifiers);
if(filteredRSs.length > 0)
{
printRSDetails(filteredRSs);
console.log(chalk.green(`Found ${filteredRSs.length} API(s) that would be deleted`));
deleteResourceServers(filteredRSs)
} else console.log(chalk.green("No resource servers matching the filters found!!!"))



