using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.tls
{

	using DHParameters = org.bouncycastle.crypto.@params.DHParameters;
	using DHPublicKeyParameters = org.bouncycastle.crypto.@params.DHPublicKeyParameters;
	using TeeInputStream = org.bouncycastle.util.io.TeeInputStream;

	public class TlsDHEKeyExchange : TlsDHKeyExchange
	{
		protected internal TlsSignerCredentials serverCredentials = null;

		/// @deprecated Use constructor that takes a TlsDHVerifier 
		public TlsDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, DHParameters dhParameters) : this(keyExchange, supportedSignatureAlgorithms, new DefaultTlsDHVerifier(), dhParameters)
		{
		}

		public TlsDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsDHVerifier dhVerifier, DHParameters dhParameters) : base(keyExchange, supportedSignatureAlgorithms, dhVerifier, dhParameters)
		{
		}

		public override void processServerCredentials(TlsCredentials serverCredentials)
		{
			if (!(serverCredentials is TlsSignerCredentials))
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			processServerCertificate(serverCredentials.getCertificate());

			this.serverCredentials = (TlsSignerCredentials)serverCredentials;
		}

		public override byte[] generateServerKeyExchange()
		{
			if (this.dhParameters == null)
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			DigestInputBuffer buf = new DigestInputBuffer();

			this.dhAgreePrivateKey = TlsDHUtils.generateEphemeralServerKeyExchange(context.getSecureRandom(), this.dhParameters, buf);

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

			return buf.toByteArray();
		}

		public override void processServerKeyExchange(InputStream input)
		{
			SecurityParameters securityParameters = context.getSecurityParameters();

			SignerInputBuffer buf = new SignerInputBuffer();
			InputStream teeIn = new TeeInputStream(input, buf);

			this.dhParameters = TlsDHUtils.receiveDHParameters(dhVerifier, teeIn);
			this.dhAgreePublicKey = new DHPublicKeyParameters(TlsDHUtils.readDHParameter(teeIn), dhParameters);

			DigitallySigned signed_params = parseSignature(input);

			Signer signer = initVerifyer(tlsSigner, signed_params.getAlgorithm(), securityParameters);
			buf.updateSigner(signer);
			if (!signer.verifySignature(signed_params.getSignature()))
			{
				throw new TlsFatalAlert(AlertDescription.decrypt_error);
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