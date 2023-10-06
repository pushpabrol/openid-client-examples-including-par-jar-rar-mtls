import crypto from 'crypto';
import fs from 'fs';
import forge from 'node-forge';
import readline from 'readline';

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// Function to calculate and display the thumbprint
function calculateThumbprint(pemCertificatePath) {
  try {
    // Load the PEM certificate from the specified file
    const pemCertificate = fs.readFileSync(pemCertificatePath, 'utf8');

    // Parse the PEM certificate
    const cert = forge.pki.certificateFromPem(pemCertificate);

    // Convert the certificate to DER format
    const derCertificate = forge.asn1.toDer(forge.pki.certificateToAsn1(cert));

    // Calculate the SHA-256 thumbprint of the certificate
    const thumbprint = crypto
      .createHash('sha256')
      .update(Buffer.from(derCertificate.getBytes(), 'binary'))
      .digest();

    // Encode the thumbprint as base64 URL-safe string
    const base64Thumbprint = Buffer.from(thumbprint)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    console.log('x5t#S256:', base64Thumbprint);
  } catch (error) {
    console.error('Error:', error.message);
  }
}

// Ask the user for the path of the PEM file
rl.question('Enter the path of the PEM file: ', (answer) => {
  calculateThumbprint(answer);
  rl.close();
});
