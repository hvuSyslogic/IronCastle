using org.bouncycastle.asn1.x509;

using System;

namespace org.bouncycastle.crypto.tls.test
{

	using RSAPrivateKey = org.bouncycastle.asn1.pkcs.RSAPrivateKey;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using RSAPrivateCrtKeyParameters = org.bouncycastle.crypto.@params.RSAPrivateCrtKeyParameters;
	using PrivateKeyFactory = org.bouncycastle.crypto.util.PrivateKeyFactory;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using PemObject = org.bouncycastle.util.io.pem.PemObject;
	using PemReader = org.bouncycastle.util.io.pem.PemReader;

	public class TlsTestUtils
	{
		internal static readonly byte[] rsaCertData = Base64.decode("MIICUzCCAf2gAwIBAgIBATANBgkqhkiG9w0BAQQFADCBjzELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb2" + "4gb2YgdGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExLzAtBgkq" + "hkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMB4XDTEzMDIyNTA2MDIwNVoXDTEzMDIyNT" + "A2MDM0NVowgY8xCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIw" + "EAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG" + "9AYm91bmN5Y2FzdGxlLm9yZzBaMA0GCSqGSIb3DQEBAQUAA0kAMEYCQQC0p+RhcFdPFqlwgrIr5YtqKmKXmEGb4Shy" + "pL26Ymz66ZAPdqv7EhOdzl3lZWT6srZUMWWgQMYGiHQg4z2R7X7XAgERo0QwQjAOBgNVHQ8BAf8EBAMCBSAwEgYDVR" + "0lAQH/BAgwBgYEVR0lADAcBgNVHREBAf8EEjAQgQ50ZXN0QHRlc3QudGVzdDANBgkqhkiG9w0BAQQFAANBAHU55Ncz" + "eglREcTg54YLUlGWu2WOYWhit/iM1eeq8Kivro7q98eW52jTuMI3CI5ulqd0hYzshQKQaZ5GDzErMyM=");

		internal static readonly byte[] dudRsaCertData = Base64.decode("MIICUzCCAf2gAwIBAgIBATANBgkqhkiG9w0BAQQFADCBjzELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb2" + "4gb2YgdGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExLzAtBgkq" + "hkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMB4XDTEzMDIyNTA1NDcyOFoXDTEzMDIyNT" + "A1NDkwOFowgY8xCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIw" + "EAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG" + "9AYm91bmN5Y2FzdGxlLm9yZzBaMA0GCSqGSIb3DQEBAQUAA0kAMEYCQQC0p+RhcFdPFqlwgrIr5YtqKmKXmEGb4Shy" + "pL26Ymz66ZAPdqv7EhOdzl3lZWT6srZUMWWgQMYGiHQg4z2R7X7XAgERo0QwQjAOBgNVHQ8BAf8EBAMCAAEwEgYDVR" + "0lAQH/BAgwBgYEVR0lADAcBgNVHREBAf8EEjAQgQ50ZXN0QHRlc3QudGVzdDANBgkqhkiG9w0BAQQFAANBAJg55PBS" + "weg6obRUKF4FF6fCrWFi6oCYSQ99LWcAeupc5BofW5MstFMhCOaEucuGVqunwT5G7/DweazzCIrSzB0=");

		internal static string fingerprint(Certificate c)
		{
			byte[] der = c.getEncoded();
			byte[] sha1 = sha256DigestOf(der);
			byte[] hexBytes = Hex.encode(sha1);
			string hex = (StringHelper.NewString(hexBytes, "ASCII")).ToUpper();

			StringBuffer fp = new StringBuffer();
			int i = 0;
			fp.append(hex.Substring(i, 2));
			while ((i += 2) < hex.Length)
			{
				fp.append(':');
				fp.append(hex.Substring(i, 2));
			}
			return fp.ToString();
		}

		internal static byte[] sha256DigestOf(byte[] input)
		{
			SHA256Digest d = new SHA256Digest();
			d.update(input, 0, input.Length);
			byte[] result = new byte[d.getDigestSize()];
			d.doFinal(result, 0);
			return result;
		}

		internal static TlsAgreementCredentials loadAgreementCredentials(TlsContext context, string[] certResources, string keyResource)
		{
			Certificate certificate = loadCertificateChain(certResources);
			AsymmetricKeyParameter privateKey = loadPrivateKeyResource(keyResource);

			return new DefaultTlsAgreementCredentials(certificate, privateKey);
		}

		internal static TlsEncryptionCredentials loadEncryptionCredentials(TlsContext context, string[] certResources, string keyResource)
		{
			Certificate certificate = loadCertificateChain(certResources);
			AsymmetricKeyParameter privateKey = loadPrivateKeyResource(keyResource);

			return new DefaultTlsEncryptionCredentials(context, certificate, privateKey);
		}

		internal static TlsSignerCredentials loadSignerCredentials(TlsContext context, string[] certResources, string keyResource, SignatureAndHashAlgorithm signatureAndHashAlgorithm)
		{
			Certificate certificate = loadCertificateChain(certResources);
			AsymmetricKeyParameter privateKey = loadPrivateKeyResource(keyResource);

			return new DefaultTlsSignerCredentials(context, certificate, privateKey, signatureAndHashAlgorithm);
		}

		internal static TlsSignerCredentials loadSignerCredentials(TlsContext context, Vector supportedSignatureAlgorithms, short signatureAlgorithm, string certResource, string keyResource)
		{
			/*
			 * TODO Note that this code fails to provide default value for the client supported
			 * algorithms if it wasn't sent.
			 */

			SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
			if (supportedSignatureAlgorithms != null)
			{
				for (int i = 0; i < supportedSignatureAlgorithms.size(); ++i)
				{
					SignatureAndHashAlgorithm alg = (SignatureAndHashAlgorithm) supportedSignatureAlgorithms.elementAt(i);
					if (alg.getSignature() == signatureAlgorithm)
					{
						signatureAndHashAlgorithm = alg;
						break;
					}
				}

				if (signatureAndHashAlgorithm == null)
				{
					return null;
				}
			}

			return loadSignerCredentials(context, new string[]{certResource, "x509-ca.pem"}, keyResource, signatureAndHashAlgorithm);
		}

		internal static Certificate loadCertificateChain(string[] resources)
		{
			Certificate[] chain = new Certificate[resources.Length];
			for (int i = 0; i < resources.Length; ++i)
			{
				chain[i] = loadCertificateResource(resources[i]);
			}
			return new Certificate(chain);
		}

		internal static Certificate loadCertificateResource(string resource)
		{
			PemObject pem = loadPemResource(resource);
			if (pem.getType().EndsWith("CERTIFICATE", StringComparison.Ordinal))
			{
				return Certificate.getInstance(pem.getContent());
			}
			throw new IllegalArgumentException("'resource' doesn't specify a valid certificate");
		}

		internal static AsymmetricKeyParameter loadPrivateKeyResource(string resource)
		{
			PemObject pem = loadPemResource(resource);
			if (pem.getType().EndsWith("RSA PRIVATE KEY", StringComparison.Ordinal))
			{
				RSAPrivateKey rsa = RSAPrivateKey.getInstance(pem.getContent());
				return new RSAPrivateCrtKeyParameters(rsa.getModulus(), rsa.getPublicExponent(), rsa.getPrivateExponent(), rsa.getPrime1(), rsa.getPrime2(), rsa.getExponent1(), rsa.getExponent2(), rsa.getCoefficient());
			}
			if (pem.getType().EndsWith("PRIVATE KEY", StringComparison.Ordinal))
			{
				return PrivateKeyFactory.createKey(pem.getContent());
			}
			throw new IllegalArgumentException("'resource' doesn't specify a valid private key");
		}

		internal static PemObject loadPemResource(string resource)
		{
			InputStream s = typeof(TlsTestUtils).getResourceAsStream(resource);
			PemReader p = new PemReader(new InputStreamReader(s));
			PemObject o = p.readPemObject();
			p.close();
			return o;
		}
	}

}