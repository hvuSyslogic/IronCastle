using org.bouncycastle.asn1.x509;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.crypto.util;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util.io;

namespace org.bouncycastle.crypto.tls
{

						
	/// <summary>
	/// (D)TLS and SSLv3 RSA key exchange.
	/// </summary>
	public class TlsRSAKeyExchange : AbstractTlsKeyExchange
	{
		protected internal AsymmetricKeyParameter serverPublicKey = null;

		protected internal RSAKeyParameters rsaServerPublicKey = null;

		protected internal TlsEncryptionCredentials serverCredentials = null;

		protected internal byte[] premasterSecret;

		public TlsRSAKeyExchange(Vector supportedSignatureAlgorithms) : base(KeyExchangeAlgorithm.RSA, supportedSignatureAlgorithms)
		{
		}

		public override void skipServerCredentials()
		{
			throw new TlsFatalAlert(AlertDescription.unexpected_message);
		}

		public override void processServerCredentials(TlsCredentials serverCredentials)
		{
			if (!(serverCredentials is TlsEncryptionCredentials))
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			processServerCertificate(serverCredentials.getCertificate());

			this.serverCredentials = (TlsEncryptionCredentials)serverCredentials;
		}

		public override void processServerCertificate(Certificate serverCertificate)
		{
			if (serverCertificate.isEmpty())
			{
				throw new TlsFatalAlert(AlertDescription.bad_certificate);
			}

		    org.bouncycastle.asn1.x509.Certificate x509Cert = serverCertificate.getCertificateAt(0);

			SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();
			try
			{
				this.serverPublicKey = PublicKeyFactory.createKey(keyInfo);
			}
			catch (RuntimeException e)
			{
				throw new TlsFatalAlert(AlertDescription.unsupported_certificate, e);
			}

			// Sanity check the PublicKeyFactory
			if (this.serverPublicKey.isPrivate())
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			this.rsaServerPublicKey = validateRSAPublicKey((RSAKeyParameters)this.serverPublicKey);

			TlsUtils.validateKeyUsage(x509Cert, KeyUsage.keyEncipherment);

			base.processServerCertificate(serverCertificate);
		}

		public override void validateCertificateRequest(CertificateRequest certificateRequest)
		{
			short[] types = certificateRequest.getCertificateTypes();
			for (int i = 0; i < types.Length; ++i)
			{
				switch (types[i])
				{
				case ClientCertificateType.rsa_sign:
				case ClientCertificateType.dss_sign:
				case ClientCertificateType.ecdsa_sign:
					break;
				default:
					throw new TlsFatalAlert(AlertDescription.illegal_parameter);
				}
			}
		}

		public override void processClientCredentials(TlsCredentials clientCredentials)
		{
			if (!(clientCredentials is TlsSignerCredentials))
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		public override void generateClientKeyExchange(OutputStream output)
		{
			this.premasterSecret = TlsRSAUtils.generateEncryptedPreMasterSecret(context, rsaServerPublicKey, output);
		}

		public override void processClientKeyExchange(InputStream input)
		{
			byte[] encryptedPreMasterSecret;
			if (TlsUtils.isSSL(context))
			{
				// TODO Do any SSLv3 clients actually include the length?
				encryptedPreMasterSecret = Streams.readAll(input);
			}
			else
			{
				encryptedPreMasterSecret = TlsUtils.readOpaque16(input);
			}

			this.premasterSecret = serverCredentials.decryptPreMasterSecret(encryptedPreMasterSecret);
		}

		public override byte[] generatePremasterSecret()
		{
			if (this.premasterSecret == null)
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			byte[] tmp = this.premasterSecret;
			this.premasterSecret = null;
			return tmp;
		}

		// Would be needed to process RSA_EXPORT server key exchange
		// protected void processRSAServerKeyExchange(InputStream is, Signer signer) throws IOException
		// {
		// InputStream sigIn = is;
		// if (signer != null)
		// {
		// sigIn = new SignerInputStream(is, signer);
		// }
		//
		// byte[] modulusBytes = TlsUtils.readOpaque16(sigIn);
		// byte[] exponentBytes = TlsUtils.readOpaque16(sigIn);
		//
		// if (signer != null)
		// {
		// byte[] sigByte = TlsUtils.readOpaque16(is);
		//
		// if (!signer.verifySignature(sigByte))
		// {
		// handler.failWithError(AlertLevel.fatal, AlertDescription.bad_certificate);
		// }
		// }
		//
		// BigInteger modulus = new BigInteger(1, modulusBytes);
		// BigInteger exponent = new BigInteger(1, exponentBytes);
		//
		// this.rsaServerPublicKey = validateRSAPublicKey(new RSAKeyParameters(false, modulus,
		// exponent));
		// }

		public virtual RSAKeyParameters validateRSAPublicKey(RSAKeyParameters key)
		{
			// TODO What is the minimum bit length required?
			// key.getModulus().bitLength();

			if (!key.getExponent().isProbablePrime(2))
			{
				throw new TlsFatalAlert(AlertDescription.illegal_parameter);
			}

			return key;
		}
	}

}