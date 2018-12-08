using BouncyCastle.Core.Port;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.tls
{

	using KeyUsage = org.bouncycastle.asn1.x509.KeyUsage;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using SRP6Client = org.bouncycastle.crypto.agreement.srp.SRP6Client;
	using SRP6Server = org.bouncycastle.crypto.agreement.srp.SRP6Server;
	using SRP6Util = org.bouncycastle.crypto.agreement.srp.SRP6Util;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using SRP6GroupParameters = org.bouncycastle.crypto.@params.SRP6GroupParameters;
	using PublicKeyFactory = org.bouncycastle.crypto.util.PublicKeyFactory;
	using Arrays = org.bouncycastle.util.Arrays;
	using BigIntegers = org.bouncycastle.util.BigIntegers;
	using TeeInputStream = org.bouncycastle.util.io.TeeInputStream;

	/// <summary>
	/// (D)TLS SRP key exchange (RFC 5054).
	/// </summary>
	public class TlsSRPKeyExchange : AbstractTlsKeyExchange
	{
		protected internal static TlsSigner createSigner(int keyExchange)
		{
			switch (keyExchange)
			{
			case KeyExchangeAlgorithm.SRP:
				return null;
			case KeyExchangeAlgorithm.SRP_RSA:
				return new TlsRSASigner();
			case KeyExchangeAlgorithm.SRP_DSS:
				return new TlsDSSSigner();
			default:
				throw new IllegalArgumentException("unsupported key exchange algorithm");
			}
		}

		protected internal TlsSigner tlsSigner;
		protected internal TlsSRPGroupVerifier groupVerifier;
		protected internal byte[] identity;
		protected internal byte[] password;

		protected internal AsymmetricKeyParameter serverPublicKey = null;

		protected internal SRP6GroupParameters srpGroup = null;
		protected internal SRP6Client srpClient = null;
		protected internal SRP6Server srpServer = null;
		protected internal BigInteger srpPeerCredentials = null;
		protected internal BigInteger srpVerifier = null;
		protected internal byte[] srpSalt = null;

		protected internal TlsSignerCredentials serverCredentials = null;

		/// @deprecated Use constructor taking an explicit 'groupVerifier' argument 
		public TlsSRPKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, byte[] identity, byte[] password) : this(keyExchange, supportedSignatureAlgorithms, new DefaultTlsSRPGroupVerifier(), identity, password)
		{
		}

		public TlsSRPKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsSRPGroupVerifier groupVerifier, byte[] identity, byte[] password) : base(keyExchange, supportedSignatureAlgorithms)
		{

			this.tlsSigner = createSigner(keyExchange);
			this.groupVerifier = groupVerifier;
			this.identity = identity;
			this.password = password;
			this.srpClient = new SRP6Client();
		}

		public TlsSRPKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, byte[] identity, TlsSRPLoginParameters loginParameters) : base(keyExchange, supportedSignatureAlgorithms)
		{

			this.tlsSigner = createSigner(keyExchange);
			this.identity = identity;
			this.srpServer = new SRP6Server();
			this.srpGroup = loginParameters.getGroup();
			this.srpVerifier = loginParameters.getVerifier();
			this.srpSalt = loginParameters.getSalt();
		}

		public override void init(TlsContext context)
		{
			base.init(context);

			if (this.tlsSigner != null)
			{
				this.tlsSigner.init(context);
			}
		}

		public override void skipServerCredentials()
		{
			if (tlsSigner != null)
			{
				throw new TlsFatalAlert(AlertDescription.unexpected_message);
			}
		}

		public override void processServerCertificate(Certificate serverCertificate)
		{
			if (tlsSigner == null)
			{
				throw new TlsFatalAlert(AlertDescription.unexpected_message);
			}
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

			if (!tlsSigner.isValidPublicKey(this.serverPublicKey))
			{
				throw new TlsFatalAlert(AlertDescription.certificate_unknown);
			}

			TlsUtils.validateKeyUsage(x509Cert, KeyUsage.digitalSignature);

			base.processServerCertificate(serverCertificate);
		}

		public override void processServerCredentials(TlsCredentials serverCredentials)
		{
			if ((keyExchange == KeyExchangeAlgorithm.SRP) || !(serverCredentials is TlsSignerCredentials))
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			processServerCertificate(serverCredentials.getCertificate());

			this.serverCredentials = (TlsSignerCredentials)serverCredentials;
		}

		public override bool requiresServerKeyExchange()
		{
			return true;
		}

		public override byte[] generateServerKeyExchange()
		{
			srpServer.init(srpGroup, srpVerifier, TlsUtils.createHash(HashAlgorithm.sha1), context.getSecureRandom());
			BigInteger B = srpServer.generateServerCredentials();

			ServerSRPParams srpParams = new ServerSRPParams(srpGroup.getN(), srpGroup.getG(), srpSalt, B);

			DigestInputBuffer buf = new DigestInputBuffer();

			srpParams.encode(buf);

			if (serverCredentials != null)
			{
				/*
				 * RFC 5246 4.7. digitally-signed element needs SignatureAndHashAlgorithm from TLS 1.2
				 */
				SignatureAndHashAlgorithm signatureAndHashAlgorithm = TlsUtils.getSignatureAndHashAlgorithm(context, serverCredentials);

				Digest d = TlsUtils.createHash(signatureAndHashAlgorithm);

				SecurityParameters securityParameters = context.getSecurityParameters();
				d.update(securityParameters.clientRandom, 0, securityParameters.clientRandom.Length);
				d.update(securityParameters.serverRandom, 0, securityParameters.serverRandom.Length);
				buf.updateDigest(d);

				byte[] hash = new byte[d.getDigestSize()];
				d.doFinal(hash, 0);

				byte[] signature = serverCredentials.generateCertificateSignature(hash);

				DigitallySigned signed_params = new DigitallySigned(signatureAndHashAlgorithm, signature);
				signed_params.encode(buf);
			}

			return buf.toByteArray();
		}

		public override void processServerKeyExchange(InputStream input)
		{
			SecurityParameters securityParameters = context.getSecurityParameters();

			SignerInputBuffer buf = null;
			InputStream teeIn = input;

			if (tlsSigner != null)
			{
				buf = new SignerInputBuffer();
				teeIn = new TeeInputStream(input, buf);
			}

			ServerSRPParams srpParams = ServerSRPParams.parse(teeIn);

			if (buf != null)
			{
				DigitallySigned signed_params = parseSignature(input);

				Signer signer = initVerifyer(tlsSigner, signed_params.getAlgorithm(), securityParameters);
				buf.updateSigner(signer);
				if (!signer.verifySignature(signed_params.getSignature()))
				{
					throw new TlsFatalAlert(AlertDescription.decrypt_error);
				}
			}

			this.srpGroup = new SRP6GroupParameters(srpParams.getN(), srpParams.getG());

			if (!groupVerifier.accept(srpGroup))
			{
				throw new TlsFatalAlert(AlertDescription.insufficient_security);
			}

			this.srpSalt = srpParams.getS();

			/*
			 * RFC 5054 2.5.3: The client MUST abort the handshake with an "illegal_parameter" alert if
			 * B % N = 0.
			 */
			try
			{
				this.srpPeerCredentials = SRP6Util.validatePublicValue(srpGroup.getN(), srpParams.getB());
			}
			catch (CryptoException e)
			{
				throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
			}

			this.srpClient.init(srpGroup, TlsUtils.createHash(HashAlgorithm.sha1), context.getSecureRandom());
		}

		public override void validateCertificateRequest(CertificateRequest certificateRequest)
		{
			throw new TlsFatalAlert(AlertDescription.unexpected_message);
		}

		public override void processClientCredentials(TlsCredentials clientCredentials)
		{
			throw new TlsFatalAlert(AlertDescription.internal_error);
		}

		public override void generateClientKeyExchange(OutputStream output)
		{
			BigInteger A = srpClient.generateClientCredentials(srpSalt, identity, password);
			TlsSRPUtils.writeSRPParameter(A, output);

			context.getSecurityParameters().srpIdentity = Arrays.clone(identity);
		}

		public override void processClientKeyExchange(InputStream input)
		{
			/*
			 * RFC 5054 2.5.4: The server MUST abort the handshake with an "illegal_parameter" alert if
			 * A % N = 0.
			 */
			try
			{
				this.srpPeerCredentials = SRP6Util.validatePublicValue(srpGroup.getN(), TlsSRPUtils.readSRPParameter(input));
			}
			catch (CryptoException e)
			{
				throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
			}

			context.getSecurityParameters().srpIdentity = Arrays.clone(identity);
		}

		public override byte[] generatePremasterSecret()
		{
			try
			{
				BigInteger S = srpServer != null ? srpServer.calculateSecret(srpPeerCredentials) : srpClient.calculateSecret(srpPeerCredentials);

				// TODO Check if this needs to be a fixed size
				return BigIntegers.asUnsignedByteArray(S);
			}
			catch (CryptoException e)
			{
				throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
			}
		}

		public virtual Signer initVerifyer(TlsSigner tlsSigner, SignatureAndHashAlgorithm algorithm, SecurityParameters securityParameters)
		{
			Signer signer = tlsSigner.createVerifyer(algorithm, this.serverPublicKey);
			signer.update(securityParameters.clientRandom, 0, securityParameters.clientRandom.Length);
			signer.update(securityParameters.serverRandom, 0, securityParameters.serverRandom.Length);
			return signer;
		}
	}

}