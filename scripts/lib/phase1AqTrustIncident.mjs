import { X509Certificate } from 'node:crypto';

// Phase 1AQ: public WebPKI incident screening only. NOT a PKIX or provider
// authorization validator. Mozilla Bug 2083449, Appendix A/B/C (2026-11).
// Keep the original CA certificates, cross-signs and later RSA G2 scope separate.
// Policy is deny-only: a fingerprint NOT listed is still NOT trusted.
export const INCIDENT_SOURCE = 'https://bugzilla.mozilla.org/show_bug.cgi?id=2083449';
export const DISALLOWED_WEBPKI_SHA256 = Object.freeze({
  G3_ORIGINAL: Object.freeze([
    'E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838',
    '98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B',
    '42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493',
    '432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3',
    'CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F',
    '0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19',
    '9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4',
    '4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1',
  ]),
  G3_CROSS_SIGNED: Object.freeze([
    '45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE',
    '62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72',
    '5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699',
    '7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489',
    '579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512',
    'FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F',
    'A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8',
    '84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD',
  ]),
  G2_RSA: Object.freeze([
    '829EC444B8BE3DFD2D030A0D9E7A1D0DD2A3C2C325D39589C27AC9A065BAE793',
    '0427EA3CB4A7B4CB205E77A7B166D332BEDB8E8EF469BC5E883169C8D0AC876D',
    '6A7A93861982B664001710A0EFD04C8A72F6A23E252B280911797E0BF1BD9012',
    'DE767792E870BD32F331029FC89DC24C53F9DF970DC70F1EA30CF29DB3F94BA9',
    'E072B30D7F5B8BCF0080E51D6CC7765767072DB2319E9BB1CD3D02A086898750',
    'C3BC2B480FB1A1AB4D0BA1ED6C7B53E096447045733620991A32D6798D77AA20',
    '913F1A04B02814B604AC5275ACB201B1C802B2C0F1B4986FB1A1EB595958E072',
    'EBAC91B8EC9853323779EDB393C595FADB29DD4DDB20C47E336F2A021684F27B',
  ]),
});
const disallowedFingerprints = new Set(Object.values(DISALLOWED_WEBPKI_SHA256).flat());
if (disallowedFingerprints.size !== 24) throw Error('Phase 1AQ incident inventory integrity failure');

function normalizeSha256(value) {
  if (typeof value !== 'string') throw TypeError('Invalid public certificate fingerprint');
  const compact = value.replaceAll(':', '').toUpperCase();
  if (!/^[0-9A-F]{64}$/.test(compact) ||
      (value.includes(':') && !/^(?:[0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}$/.test(value)))
    throw Error('Invalid SHA-256 fingerprint');
  return compact;
}

// This is a negative screen, never a trust decision. For example a cross-signed
// certificate absent from a future list must still remain HOLD.
export function classifyPhase1AqPublicFingerprint(value) {
  const fingerprint = normalizeSha256(value);
  return Object.freeze({
    knownIncidentCertificate: disallowedFingerprints.has(fingerprint),
    certificateTrustEstablished: false,
    disposition: disallowedFingerprints.has(fingerprint) ? 'DENY' : 'UNVERIFIED_HOLD'
  });
}

const singlePem = /^-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END CERTIFICATE-----\r?\n?$/;
export function auditPhase1AqPublicCertificateChain(certificates = []) {
  if (!Array.isArray(certificates) || certificates.length > 12)
    throw TypeError('Expected at most twelve public certificate PEM values');
  const seen = new Set();
  let incidentMatches = 0;
  for (const pem of certificates) {
    // Do not allow key material, concatenated PEMs, arbitrary metadata or huge blobs.
    if (typeof pem !== 'string' || Buffer.byteLength(pem, 'utf8') > 32768 ||
        !singlePem.test(pem)) throw Error('Only a single bounded public X509 certificate is accepted');
    const certificate = new X509Certificate(pem);
    const fingerprint = normalizeSha256(certificate.fingerprint256);
    if (seen.has(fingerprint)) throw Error('Repeated certificate is not a valid chain');
    seen.add(fingerprint);
    if (disallowedFingerprints.has(fingerprint)) incidentMatches += 1;
  }
  return Object.freeze({
    phase: '1AQ', checkedPublicCertificateCount: seen.size,
    knownIncidentCertificateDetected: incidentMatches > 0,
    knownIncidentCertificateCount: incidentMatches,
    incidentInventoryEntryCount: disallowedFingerprints.size,
    certificatePathAuthenticated: false,
    indianCcaDscAuthorityAuthenticated: false,
    sandboxServiceAuthorized: false,
    authenticatedLiveRevocation: false,
    mcaAndSignatoryVerified: false,
    stockPostingEnabled: false,
    productionReleaseAuthorized: false,
    releaseDecision: 'HOLD',
    blockers: Object.freeze([
      ...(incidentMatches ? ['Known publicly revoked or compromised WebPKI certificate detected: DENY'] : []),
      'No out-of-band authenticated RCAI/CCA DSC PKIX certificate chain or valid provider policy',
      'No signed provider agreement or least-privilege sandbox credentials',
      'No independently authenticated CRL/OCSP, MCA corporate record or legal delegation',
      'WebPKI incident screen cannot authorize any supplier, stock, finance or production action'
    ])
  });
}
