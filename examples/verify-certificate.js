const { OpenExecutionVerifier } = require('@openexecution/verify');

async function main() {
  const verifier = new OpenExecutionVerifier();
  const certificateId = process.argv[2];

  if (!certificateId) {
    console.error('Usage: node verify-certificate.js <certificate-id>');
    process.exit(1);
  }

  try {
    const result = await verifier.verifyCertificate(certificateId);
    console.log(JSON.stringify(result, null, 2));
    console.log(result.valid ? '\nCertificate is VALID' : '\nCertificate is INVALID');
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  }
}

main();
