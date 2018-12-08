using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.tls
{
	using NullDigest = org.bouncycastle.crypto.digests.NullDigest;
	using PKCS1Encoding = org.bouncycastle.crypto.encodings.PKCS1Encoding;
	using RSABlindedEngine = org.bouncycastle.crypto.engines.RSABlindedEngine;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using RSAKeyParameters = org.bouncycastle.crypto.@params.RSAKeyParameters;
	using GenericSigner = org.bouncycastle.crypto.signers.GenericSigner;
	using RSADigestSigner = org.bouncycastle.crypto.signers.RSADigestSigner;

	public class TlsRSASigner : AbstractTlsSigner
	{
		public override byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter privateKey, byte[] hash)
		{
			Signer signer = makeSigner(algorithm, true, true, new ParametersWithRandom(privateKey, this.context.getSecureRandom()));
			signer.update(hash, 0, hash.Length);
			return signer.generateSignature();
		}

		public override bool verifyRawSignature(SignatureAndHashAlgorithm algorithm, byte[] sigBytes, AsymmetricKeyParameter publicKey, byte[] hash)
		{
			Signer signer = makeSigner(algorithm, true, false, publicKey);
			signer.update(hash, 0, hash.Length);
			return signer.verifySignature(sigBytes);
		}

		public override Signer createSigner(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter privateKey)
		{
			return makeSigner(algorithm, false, true, new ParametersWithRandom(privateKey, this.context.getSecureRandom()));
		}

		public override Signer createVerifyer(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter publicKey)
		{
			return makeSigner(algorithm, false, false, publicKey);
		}

		public override bool isValidPublicKey(AsymmetricKeyParameter publicKey)
		{
			return publicKey is RSAKeyParameters && !publicKey.isPrivate();
		}

		public virtual Signer makeSigner(SignatureAndHashAlgorithm algorithm, bool raw, bool forSigning, CipherParameters cp)
		{
			if ((algorithm != null) != TlsUtils.isTLSv12(context))
			{
				throw new IllegalStateException();
			}

			if (algorithm != null && algorithm.getSignature() != SignatureAlgorithm.rsa)
			{
				throw new IllegalStateException();
			}

			Digest d;
			if (raw)
			{
				d = new NullDigest();
			}
			else if (algorithm == null)
			{
				d = new CombinedHash();
			}
			else
			{
				d = TlsUtils.createHash(algorithm.getHash());
			}

			Signer s;
			if (algorithm != null)
			{
				/*
				 * RFC 5246 4.7. In RSA signing, the opaque vector contains the signature generated
				 * using the RSASSA-PKCS1-v1_5 signature scheme defined in [PKCS1].
				 */
				s = new RSADigestSigner(d, TlsUtils.getOIDForHashAlgorithm(algorithm.getHash()));
			}
			else
			{
				/*
				 * RFC 5246 4.7. Note that earlier versions of TLS used a different RSA signature scheme
				 * that did not include a DigestInfo encoding.
				 */
				s = new GenericSigner(createRSAImpl(), d);
			}
			s.init(forSigning, cp);
			return s;
		}

		public virtual AsymmetricBlockCipher createRSAImpl()
		{
			/*
			 * RFC 5246 7.4.7.1. Implementation note: It is now known that remote timing-based attacks
			 * on TLS are possible, at least when the client and server are on the same LAN.
			 * Accordingly, implementations that use static RSA keys MUST use RSA blinding or some other
			 * anti-timing technique, as described in [TIMING].
			 */
			return new PKCS1Encoding(new RSABlindedEngine());
		}
	}

}