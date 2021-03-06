﻿using org.bouncycastle.asn1.x509;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.crypto.util;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;
using org.bouncycastle.util.io;

namespace org.bouncycastle.crypto.tls
{

													
	/// <summary>
	/// (D)TLS PSK key exchange (RFC 4279).
	/// </summary>
	public class TlsPSKKeyExchange : AbstractTlsKeyExchange
	{
		protected internal TlsPSKIdentity pskIdentity;
		protected internal TlsPSKIdentityManager pskIdentityManager;

		protected internal TlsDHVerifier dhVerifier;
		protected internal DHParameters dhParameters;
		protected internal int[] namedCurves;
		protected internal short[] clientECPointFormats, serverECPointFormats;

		protected internal byte[] psk_identity_hint = null;
		protected internal byte[] psk = null;

		protected internal DHPrivateKeyParameters dhAgreePrivateKey = null;
		protected internal DHPublicKeyParameters dhAgreePublicKey = null;

		protected internal ECPrivateKeyParameters ecAgreePrivateKey = null;
		protected internal ECPublicKeyParameters ecAgreePublicKey = null;

		protected internal AsymmetricKeyParameter serverPublicKey = null;
		protected internal RSAKeyParameters rsaServerPublicKey = null;
		protected internal TlsEncryptionCredentials serverCredentials = null;
		protected internal byte[] premasterSecret;

		/// @deprecated Use constructor that takes a TlsDHVerifier 
		public TlsPSKKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsPSKIdentity pskIdentity, TlsPSKIdentityManager pskIdentityManager, DHParameters dhParameters, int[] namedCurves, short[] clientECPointFormats, short[] serverECPointFormats) : this(keyExchange, supportedSignatureAlgorithms, pskIdentity, pskIdentityManager, new DefaultTlsDHVerifier(), dhParameters, namedCurves, clientECPointFormats, serverECPointFormats)
		{
		}

		public TlsPSKKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsPSKIdentity pskIdentity, TlsPSKIdentityManager pskIdentityManager, TlsDHVerifier dhVerifier, DHParameters dhParameters, int[] namedCurves, short[] clientECPointFormats, short[] serverECPointFormats) : base(keyExchange, supportedSignatureAlgorithms)
		{

			switch (keyExchange)
			{
			case KeyExchangeAlgorithm.DHE_PSK:
			case KeyExchangeAlgorithm.ECDHE_PSK:
			case KeyExchangeAlgorithm.PSK:
			case KeyExchangeAlgorithm.RSA_PSK:
				break;
			default:
				throw new IllegalArgumentException("unsupported key exchange algorithm");
			}

			this.pskIdentity = pskIdentity;
			this.pskIdentityManager = pskIdentityManager;
			this.dhVerifier = dhVerifier;
			this.dhParameters = dhParameters;
			this.namedCurves = namedCurves;
			this.clientECPointFormats = clientECPointFormats;
			this.serverECPointFormats = serverECPointFormats;
		}

		public override void skipServerCredentials()
		{
			if (keyExchange == KeyExchangeAlgorithm.RSA_PSK)
			{
				throw new TlsFatalAlert(AlertDescription.unexpected_message);
			}
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

		public override byte[] generateServerKeyExchange()
		{
			this.psk_identity_hint = pskIdentityManager.getHint();

			if (this.psk_identity_hint == null && !requiresServerKeyExchange())
			{
				return null;
			}

			ByteArrayOutputStream buf = new ByteArrayOutputStream();

			if (this.psk_identity_hint == null)
			{
				TlsUtils.writeOpaque16(TlsUtils.EMPTY_BYTES, buf);
			}
			else
			{
				TlsUtils.writeOpaque16(this.psk_identity_hint, buf);
			}

			if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
			{
				if (this.dhParameters == null)
				{
					throw new TlsFatalAlert(AlertDescription.internal_error);
				}

				this.dhAgreePrivateKey = TlsDHUtils.generateEphemeralServerKeyExchange(context.getSecureRandom(), this.dhParameters, buf);
			}
			else if (this.keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
			{
				this.ecAgreePrivateKey = TlsECCUtils.generateEphemeralServerKeyExchange(context.getSecureRandom(), namedCurves, clientECPointFormats, buf);
			}

			return buf.toByteArray();
		}

		public override void processServerCertificate(Certificate serverCertificate)
		{
			if (keyExchange != KeyExchangeAlgorithm.RSA_PSK)
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

			// Sanity check the PublicKeyFactory
			if (this.serverPublicKey.isPrivate())
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			this.rsaServerPublicKey = validateRSAPublicKey((RSAKeyParameters)this.serverPublicKey);

			TlsUtils.validateKeyUsage(x509Cert, KeyUsage.keyEncipherment);

			base.processServerCertificate(serverCertificate);
		}

		public override bool requiresServerKeyExchange()
		{
			switch (keyExchange)
			{
			case KeyExchangeAlgorithm.DHE_PSK:
			case KeyExchangeAlgorithm.ECDHE_PSK:
				return true;
			default:
				return false;
			}
		}

		public override void processServerKeyExchange(InputStream input)
		{
			this.psk_identity_hint = TlsUtils.readOpaque16(input);

			if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
			{
				this.dhParameters = TlsDHUtils.receiveDHParameters(dhVerifier, input);
				this.dhAgreePublicKey = new DHPublicKeyParameters(TlsDHUtils.readDHParameter(input), dhParameters);
			}
			else if (this.keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
			{
				ECDomainParameters ecParams = TlsECCUtils.readECParameters(namedCurves, clientECPointFormats, input);

				byte[] point = TlsUtils.readOpaque8(input);

				this.ecAgreePublicKey = TlsECCUtils.validateECPublicKey(TlsECCUtils.deserializeECPublicKey(clientECPointFormats, ecParams, point));
			}
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
			if (psk_identity_hint == null)
			{
				pskIdentity.skipIdentityHint();
			}
			else
			{
				pskIdentity.notifyIdentityHint(psk_identity_hint);
			}

			byte[] psk_identity = pskIdentity.getPSKIdentity();
			if (psk_identity == null)
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			this.psk = pskIdentity.getPSK();
			if (psk == null)
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			TlsUtils.writeOpaque16(psk_identity, output);

			context.getSecurityParameters().pskIdentity = Arrays.clone(psk_identity);

			if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
			{
				this.dhAgreePrivateKey = TlsDHUtils.generateEphemeralClientKeyExchange(context.getSecureRandom(), dhParameters, output);
			}
			else if (this.keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
			{
				this.ecAgreePrivateKey = TlsECCUtils.generateEphemeralClientKeyExchange(context.getSecureRandom(), serverECPointFormats, ecAgreePublicKey.getParameters(), output);
			}
			else if (this.keyExchange == KeyExchangeAlgorithm.RSA_PSK)
			{
				this.premasterSecret = TlsRSAUtils.generateEncryptedPreMasterSecret(context, this.rsaServerPublicKey, output);
			}
		}

		public override void processClientKeyExchange(InputStream input)
		{
			byte[] psk_identity = TlsUtils.readOpaque16(input);

			this.psk = pskIdentityManager.getPSK(psk_identity);
			if (psk == null)
			{
				throw new TlsFatalAlert(AlertDescription.unknown_psk_identity);
			}

			context.getSecurityParameters().pskIdentity = psk_identity;

			if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
			{
				this.dhAgreePublicKey = new DHPublicKeyParameters(TlsDHUtils.readDHParameter(input), dhParameters);
			}
			else if (this.keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
			{
				byte[] point = TlsUtils.readOpaque8(input);

				ECDomainParameters curve_params = this.ecAgreePrivateKey.getParameters();

				this.ecAgreePublicKey = TlsECCUtils.validateECPublicKey(TlsECCUtils.deserializeECPublicKey(serverECPointFormats, curve_params, point));
			}
			else if (this.keyExchange == KeyExchangeAlgorithm.RSA_PSK)
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
		}

		public override byte[] generatePremasterSecret()
		{
			byte[] other_secret = generateOtherSecret(psk.Length);

			ByteArrayOutputStream buf = new ByteArrayOutputStream(4 + other_secret.Length + psk.Length);
			TlsUtils.writeOpaque16(other_secret, buf);
			TlsUtils.writeOpaque16(psk, buf);

			Arrays.fill(psk, 0);
			this.psk = null;

			return buf.toByteArray();
		}

		public virtual byte[] generateOtherSecret(int pskLength)
		{
			if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
			{
				if (dhAgreePrivateKey != null)
				{
					return TlsDHUtils.calculateDHBasicAgreement(dhAgreePublicKey, dhAgreePrivateKey);
				}

				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			if (this.keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
			{
				if (ecAgreePrivateKey != null)
				{
					return TlsECCUtils.calculateECDHBasicAgreement(ecAgreePublicKey, ecAgreePrivateKey);
				}

				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			if (this.keyExchange == KeyExchangeAlgorithm.RSA_PSK)
			{
				return this.premasterSecret;
			}

			return new byte[pskLength];
		}

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