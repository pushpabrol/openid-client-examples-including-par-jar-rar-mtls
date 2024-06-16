import { fileURLToPath } from "url";
import fs from 'fs';
import forge from 'node-forge';
import path from 'path';
import {  setEnvValue } from '../helpers.js';
import chalk from 'chalk'; // Node.js file for colorful logs
const __filename = fileURLToPath(import.meta.url);
// First find out the __dirname, then resolve to one higher level in the dir tree
export const __dirname = path.resolve(path.dirname(__filename), "../../");

const createGetCACerts =  () => {
    if (fs.existsSync(`${__dirname}/helpers/MTLS/CA/ca.crt`)) {
        const caCertificatePem = fs.readFileSync(`${__dirname}/helpers/MTLS/CA/ca.crt`, 'utf8'); // Replace with your CA certificate path
        const caPrivateKeyPem = fs.readFileSync(`${__dirname}/helpers/MTLS/CA/ca.key`, 'utf8'); // Replace with your CA private key path
        setEnvValue("CA_PATH", `${__dirname}/helpers/MTLS/CA/ca.crt`);
        return { caCertificatePem, caPrivateKeyPem };
    }

    // Generate a new RSA key pair for the CA
    const caKeys = forge.pki.rsa.generateKeyPair(4096);

    // Create a CA certificate
    const caCert = forge.pki.createCertificate();
    caCert.publicKey = caKeys.publicKey;
    caCert.serialNumber = '01';
    caCert.validity.notBefore = new Date();
    caCert.validity.notAfter = new Date();
    caCert.validity.notAfter.setFullYear(caCert.validity.notBefore.getFullYear() + 10);

    const attrs = [
        {
            name: 'commonName',
            value: 'My Local CA',
        },
        {
            name: 'countryName',
            value: 'US',
        },
        {
            shortName: 'ST',
            value: 'FL',
        },
        {
            name: 'localityName',
            value: 'Lithia',
        },
        {
            name: 'organizationName',
            value: 'Okta',
        },
        {
            shortName: 'OU',
            value: 'PreSales',
        },
    ];
    caCert.setSubject(attrs);
    caCert.setIssuer(attrs);
    caCert.setExtensions([
        {
            name: 'basicConstraints',
            cA: true,
        },
        {
            name: 'keyUsage',
            keyCertSign: true,
            digitalSignature: true,
            nonRepudiation: true,
            keyEncipherment: true,
            dataEncipherment: true,
        },
        {
            name: 'extKeyUsage',
            serverAuth: true,
            clientAuth: true,
        },
    ]);

    // Self-sign the CA certificate
    caCert.sign(caKeys.privateKey, forge.md.sha256.create());

    // Save the CA certificate and private key to files
    fs.writeFileSync(`${__dirname}/helpers/MTLS/CA/ca.crt`, forge.pki.certificateToPem(caCert));
    fs.writeFileSync(`${__dirname}/helpers/MTLS/CA/ca.key`, forge.pki.privateKeyToPem(caKeys.privateKey));
    setEnvValue("CA_PATH", `${__dirname}/helpers/MTLS/CA/ca.crt`);
    console.log(chalk.green('CA certificate and key generated, saved.'));
    return {
        caCertificatePem: fs.readFileSync(`${__dirname}/helpers/MTLS/CA/ca.crt`, 'utf8'),
        caPrivateKeyPem: fs.readFileSync(`${__dirname}/helpers/MTLS/CA/ca.key`, 'utf8')
    }




}

const { caCertificatePem, caPrivateKeyPem } = createGetCACerts()

const caCertificate = forge.pki.certificateFromPem(caCertificatePem);
const caPrivateKey = forge.pki.privateKeyFromPem(caPrivateKeyPem);

// Default values for countryName, organizationName, and organizationalUnitName
const defaultCountryName = 'US';
const defaultOrganizationName = 'Okta';
const defaultOrganizationalUnitName = 'PreSales';

// Prompt the user for the Common Name
export const createCASignedClientCert = (commonName) => {
    // Use default values for the other attributes
    const countryName = defaultCountryName;
    const organizationName = defaultOrganizationName;
    const organizationalUnitName = defaultOrganizationalUnitName;

    const clientDir = path.join(`${__dirname}/MTLS/casignedcerts/`, commonName);
    // Create a directory with the commonName as the name
    if (!fs.existsSync(clientDir)) {
        fs.mkdirSync(clientDir, fs.create);

        // Create a new client private key and certificate request (CSR)
        const clientKeys = forge.pki.rsa.generateKeyPair(2048);
        const clientCSR = forge.pki.createCertificationRequest();

        const clientAttrs = [
            { name: 'commonName', value: commonName },
            { name: 'countryName', value: countryName },
            { name: 'organizationName', value: organizationName },
            { name: 'organizationalUnitName', value: organizationalUnitName },
        ];

        clientCSR.publicKey = clientKeys.publicKey;
        clientCSR.setSubject(clientAttrs);
        clientCSR.sign(clientKeys.privateKey);

        // Generate and sign a certificate based on the CSR
        const clientCertificate = forge.pki.createCertificate();
        clientCertificate.publicKey = clientCSR.publicKey;

        // Set certificate fields (e.g., validity, subject, issuer)
        clientCertificate.validity.notBefore = new Date();
        clientCertificate.validity.notAfter = new Date();
        clientCertificate.validity.notAfter.setFullYear(clientCertificate.validity.notBefore.getFullYear() + 1);

        clientCertificate.setSubject(clientCSR.subject.attributes);
        clientCertificate.setIssuer(caCertificate.subject.attributes);

        // Sign the client certificate with the CA private key
        clientCertificate.sign(caPrivateKey,forge.md.sha256.create());

        // Convert the client certificate and private key to PEM format
        const clientCertificatePem = forge.pki.certificateToPem(clientCertificate);
        const clientPrivateKeyPem = forge.pki.privateKeyToPem(clientKeys.privateKey);

        // Save the client certificate and private key to files in the client directory
        const clientCertificatePath = path.join(clientDir, 'client-certificate.pem');
        const clientPrivateKeyPath = path.join(clientDir, 'client-private-key.pem');

        fs.writeFileSync(clientCertificatePath, clientCertificatePem);
        fs.writeFileSync(clientPrivateKeyPath, clientPrivateKeyPem);

        console.log(chalk.green(`Client certificate and private key saved in directory: ${commonName}`));

        // Create a PFX (PKCS#12) file with a password
        const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
            clientKeys.privateKey, [clientCertificate], 'Auth0Dem0'
        );

        const p12Der = forge.asn1.toDer(p12Asn1).getBytes();

        // Save the PFX file to disk in the client directory
        const pfxPath = path.join(clientDir, 'client-certificate.pfx');
        fs.writeFileSync(pfxPath, p12Der, 'binary');

        console.log(chalk.green(`Client certificate PFX file saved with password "Auth0Dem0" in directory: ${commonName}`));
        return { clientCertificatePath, clientPrivateKeyPath, pfxPath }
    } else {
        console.log(chalk.yellow(`Certificate folder for commonName - ${commonName} alredy exists. use a new one!`));
        return null;
    }
};

export const createSelfSignedCerts = (commonName) => {

    // Create a directory with the commonName as the name
    const clientDir = path.join(`${__dirname}/MTLS/selfsignedcerts/`, commonName);
    // Create a directory with the commonName as the name
    if (!fs.existsSync(clientDir)) {
        fs.mkdirSync(clientDir, fs.create);

        // Create a new client private key and certificate
        const clientKeys = forge.pki.rsa.generateKeyPair(2048);

        // Generate a self-signed certificate
        const clientCertificate = forge.pki.createCertificate();
        clientCertificate.publicKey = clientKeys.publicKey;

        // Set certificate fields (e.g., validity, subject, issuer)
        clientCertificate.validity.notBefore = new Date();
        clientCertificate.validity.notAfter = new Date();
        clientCertificate.validity.notAfter.setFullYear(clientCertificate.validity.notBefore.getFullYear() + 1);


        const clientAttrs = [
            { name: 'commonName', value: 'commonName' },
            { name: 'countryName', value: 'US' },
            { shortName: 'ST', value: 'California' },
            { name: 'localityName', value: 'San Francisco' },
            { name: 'organizationName', value: 'TPP' },
            { shortName: 'OU', value: 'IT' }
        ];

        clientCertificate.setSubject(clientAttrs);
        clientCertificate.setIssuer(clientAttrs);

        // Set certificate extensions
        clientCertificate.setExtensions([
    {
        name: 'basicConstraints',
        cA: true
    },
    {
        name: 'keyUsage',
        keyCertSign: true,
        digitalSignature: true,
        nonRepudiation: true,
        keyEncipherment: true,
        dataEncipherment: true
    },
    {
        name: 'extKeyUsage',
        serverAuth: true,
        clientAuth: true,
        codeSigning: true,
        emailProtection: true,
        timeStamping: true
    },
    {
        name: 'subjectAltName',
        altNames: [
            {
                type: 2, // DNS name
                value: 'localhost'
            },
            {
                type: 7, // IP address
                ip: '127.0.0.1'
            }
        ]
    }
]);

        // Sign the client certificate with the client private key (self-signed)
        clientCertificate.sign(clientKeys.privateKey);

        // Convert the client certificate and private key to PEM format
        const clientCertificatePem = forge.pki.certificateToPem(clientCertificate);
        const clientPrivateKeyPem = forge.pki.privateKeyToPem(clientKeys.privateKey);

        // Save the client certificate and private key to files in the client directory
        const clientCertificatePath = path.join(clientDir, 'client-certificate.pem');
        const clientPrivateKeyPath = path.join(clientDir, 'client-private-key.pem');

        fs.writeFileSync(clientCertificatePath, clientCertificatePem);
        fs.writeFileSync(clientPrivateKeyPath, clientPrivateKeyPem);

        console.log(chalk.green(`Self-signed client certificate and private key saved in directory: ${commonName}`));

        // Create a PFX (PKCS#12) file with a password
        const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
            clientKeys.privateKey, [clientCertificate], 'Auth0Dem0'
        );

        const p12Der = forge.asn1.toDer(p12Asn1).getBytes();

        // Save the PFX file to disk in the client directory
        const pfxPath = path.join(clientDir, 'client-certificate.pfx');
        fs.writeFileSync(pfxPath, p12Der, 'binary');
        console.log(chalk.green(`Self-signed client certificate PFX file saved with password "Auth0Dem0" in directory: ${commonName}`));
        return { clientCertificatePath, clientPrivateKeyPath, pfxPath }
        
    }
    else {
        console.log(chalk.yellow(`Certificate folder for Self Signed Cert with commonName - ${commonName} alredy exists. use a new one!`));
        return null;
    }
}


