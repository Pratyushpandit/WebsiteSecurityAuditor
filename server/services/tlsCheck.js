/**
 * tlsCheck.js
 * -----------------------------------------------------------------------
 * Passive TLS/certificate inspection. Opens one ordinary TLS handshake
 * (the same handshake any browser performs to load the page) and reads
 * back the negotiated protocol, cipher, and certificate metadata. It
 * does not attempt downgrade attacks, cipher fuzzing, or anything beyond
 * a standard connection.
 */

const tls = require('tls');

function checkTls(hostname, port = 443) {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      socket.destroy();
      resolve({ error: 'TLS connection timed out after 8s.' });
    }, 8000);

    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        timeout: 8000,
      },
      () => {
        clearTimeout(timeout);
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        const authorized = socket.authorized;
        const authError = socket.authorizationError;

        const validTo = cert && cert.valid_to ? new Date(cert.valid_to) : null;
        const daysRemaining = validTo ? Math.round((validTo - Date.now()) / (1000 * 60 * 60 * 24)) : null;

        socket.end();

        resolve({
          protocol,
          cipher: cipher ? cipher.name : null,
          certificateTrusted: authorized,
          trustError: authorized ? null : authError,
          certificate: cert && cert.subject
            ? {
                subject: cert.subject.CN || null,
                issuer: cert.issuer ? cert.issuer.O || cert.issuer.CN : null,
                validFrom: cert.valid_from,
                validTo: cert.valid_to,
                daysRemaining,
              }
            : null,
          isModernProtocol: protocol === 'TLSv1.3' || protocol === 'TLSv1.2',
        });
      },
    );

    socket.on('error', (err) => {
      clearTimeout(timeout);
      resolve({ error: `TLS connection failed: ${err.message}` });
    });
  });
}

module.exports = { checkTls };
