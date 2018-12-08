using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.tls
{

	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using TeeInputStream = org.bouncycastle.util.io.TeeInputStream;

	/// <summary>
	/// (D)TLS ECDHE key exchange (see RFC 4492).
	/// </summary>
	public class TlsECDHEKeyExchange : TlsECDHKeyExchange
	{
		protected internal TlsSignerCredentials serverCredentials = null;

		public TlsECDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, int[] namedCurves, short[] clientECPointFormats, short[] serverECPointFormats) : base(keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats, serverECPointFormats)
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
			DigestInputBuffer buf = new DigestInputBuffer();

			this.ecAgreePrivateKey = TlsECCUtils.generateEphemeralServerKeyExchange(context.getSecureRandom(), namedCurves, clientECPointFormats, buf);

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

			ECDomainParameters curve_params = TlsECCUtils.readECParameters(namedCurves, clientECPointFormats, teeIn);

			byte[] point = TlsUtils.readOpaque8(teeIn);

			DigitallySigned signed_params = parseSignature(input);

			Signer signer = initVerifyer(tlsSigner, signed_params.getAlgorithm(), securityParameters);
			buf.updateSigner(signer);
			if (!signer.verifySignature(signed_params.getSignature()))
			{
				throw new TlsFatalAlert(AlertDescription.decrypt_error);
			}

			this.ecAgreePublicKey = TlsECCUtils.validateECPublicKey(TlsECCUtils.deserializeECPublicKey(clientECPointFormats, curve_params, point));
		}

		public override void validateCertificateRequest(CertificateRequest certificateRequest)
		{
			/*
			 * RFC 4492 3. [...] The ECDSA_fixed_ECDH and RSA_fixed_ECDH mechanisms are usable with
			 * ECDH_ECDSA and ECDH_RSA. Their use with ECDHE_ECDSA and ECDHE_RSA is prohibited because
			 * the use of a long-term ECDH client key would jeopardize the forward secrecy property of
			 * these algorithms.
			 */
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
			if (clientCredentials is TlsSignerCredentials)
			{
				// OK
			}
			else
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
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