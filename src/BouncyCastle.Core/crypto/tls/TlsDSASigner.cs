using org.bouncycastle.crypto.digests;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.crypto.signers;
using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.tls
{
				
	public abstract class TlsDSASigner : AbstractTlsSigner
	{
		public override byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter privateKey, byte[] hash)
		{
			Signer signer = makeSigner(algorithm, true, true, new ParametersWithRandom(privateKey, this.context.getSecureRandom()));
			if (algorithm == null)
			{
				// Note: Only use the SHA1 part of the (MD5/SHA1) hash
				signer.update(hash, 16, 20);
			}
			else
			{
				signer.update(hash, 0, hash.Length);
			}
			return signer.generateSignature();
		}

		public override bool verifyRawSignature(SignatureAndHashAlgorithm algorithm, byte[] sigBytes, AsymmetricKeyParameter publicKey, byte[] hash)
		{
			Signer signer = makeSigner(algorithm, true, false, publicKey);
			if (algorithm == null)
			{
				// Note: Only use the SHA1 part of the (MD5/SHA1) hash
				signer.update(hash, 16, 20);
			}
			else
			{
				signer.update(hash, 0, hash.Length);
			}
			return signer.verifySignature(sigBytes);
		}

		public override Signer createSigner(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter privateKey)
		{
			return makeSigner(algorithm, false, true, privateKey);
		}

		public override Signer createVerifyer(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter publicKey)
		{
			return makeSigner(algorithm, false, false, publicKey);
		}

		public virtual CipherParameters makeInitParameters(bool forSigning, CipherParameters cp)
		{
			return cp;
		}

		public virtual Signer makeSigner(SignatureAndHashAlgorithm algorithm, bool raw, bool forSigning, CipherParameters cp)
		{
			if ((algorithm != null) != TlsUtils.isTLSv12(context))
			{
				throw new IllegalStateException();
			}

			if (algorithm != null && algorithm.getSignature() != getSignatureAlgorithm())
			{
				throw new IllegalStateException();
			}

			short hashAlgorithm = algorithm == null ? HashAlgorithm.sha1 : algorithm.getHash();
			Digest d = raw ? new NullDigest() : TlsUtils.createHash(hashAlgorithm);

			Signer s = new DSADigestSigner(createDSAImpl(hashAlgorithm), d);
			s.init(forSigning, makeInitParameters(forSigning, cp));
			return s;
		}

		public abstract short getSignatureAlgorithm();

		public abstract DSA createDSAImpl(short hashAlgorithm);
	}

}