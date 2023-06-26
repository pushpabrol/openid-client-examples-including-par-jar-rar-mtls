import dotenv from 'dotenv'
import {  __dirname } from './helpers.js';
import { ManagementClient } from 'auth0';
dotenv.config(`${__dirname}/.env`)

// Create a new instance of the ManagementClient
const auth0 = new ManagementClient({
    domain: process.env.DOMAIN,
    clientId: process.env.MGMT_CLIENT_ID,
    clientSecret: process.env.MGMT_CLIENT_SECRET,
});

// List all clients with pagination
const getAllClients = async () => {
    try {
      let page = 0;
      let clients = [];
  
      while (true) {
        const result = await auth0.getClients({
          page: page,
          per_page: 100,
          fields: 'client_id,name,callbacks,app_type',
          include_fields: true // Adjust the number of clients per page as needed
        });
  
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

  const filterResourceServersByName = (reseourceservers, nameFilters) => {
    const filteredRSs = reseourceservers.filter((rs) => {
      for (const filter of nameFilters) {
        if (rs.name.toLowerCase().startsWith(filter.toLowerCase())) {
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
        const result = await auth0.getResourceServers({
          page: page,
          per_page: 100,
          fields: 'id,name,identifier',
          include_fields: true // Adjust the number of reseourceservers per page as needed
        });
  
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
      console.log(`Client Name: ${client.name}`);
      console.log(`Client ID: ${client.client_id}`);
      console.log(`Client Callbacks: ${client.callbacks}`);
      console.log(`Client Type: ${client.app_type}`);
      console.log('-------------------');
    });
  };

  const printRSNamesAndIds = (rss) => {
    rss.forEach((rs) => {
      console.log(`RS Name: ${rs.name}`);
      console.log(`RS ID: ${rs.id}`);
      console.log(`RS Audience: ${rs.identifier}`);
      console.log('-------------------');
    });
  };

// Delay function to handle rate limiting
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Function to delete clients with rate limiting protection
const deleteClients = async (clients) => {
  try {

    for (const client of clients) {
      await auth0.deleteClient({ client_id: client.client_id });
      console.log(`Deleted client with ID: ${client.client_id}`);

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
        await auth0.deleteResourceServer({ id: rs.id });
        console.log(`Deleted RS with ID: ${rs.id}`);
  
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
console.log("In this Auth0 tenant - Total number of clients ", clients.length);
var reseourceservers = await getAllResourceServers();
console.log("In this Auth0 tenant - Total number of Resource Servers ", reseourceservers.length);
const rsFilters = ["MY_API_"];
const clientFilters = ["Native_Device_FLow_Test-","RWA_CLIENT_","Native_Device_FLow_Test","SPA_Test_Client","PKJWT_CLIENT","JAR_CLIENT","JARPKJWT_CLIENT"];

var filteredClients = filterClientsByName(clients,clientFilters);
//var filteredClients = filterClientsByCallbacks(clients);
if(filteredClients.length > 0)
{
printClientNamesAndIds(filteredClients)
console.log(`Found ${filteredClients.length} clients that would be deleted`);
deleteClients(filteredClients);
} else console.log(`No clients with names matching the filters found!!!`)

var filteredRSs = filterResourceServersByName(reseourceservers,rsFilters);
if(filteredRSs.length > 0)
{
printRSNamesAndIds(filteredRSs);
console.log(`Found ${filteredRSs.length} APIs that would be deleted`);
deleteResourceServers(filteredRSs)
} else console.log("No resource servers matching the filters found!!!")



