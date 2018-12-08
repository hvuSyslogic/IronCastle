using System;

namespace org.bouncycastle.pqc.jcajce.provider.sphincs
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using Digest = org.bouncycastle.crypto.Digest;
	using SHA3Digest = org.bouncycastle.crypto.digests.SHA3Digest;
	using SHA512Digest = org.bouncycastle.crypto.digests.SHA512Digest;
	using SHA512tDigest = org.bouncycastle.crypto.digests.SHA512tDigest;
	using SPHINCS256Signer = org.bouncycastle.pqc.crypto.sphincs.SPHINCS256Signer;

	public class SignatureSpi : java.security.SignatureSpi
	{
		private readonly ASN1ObjectIdentifier treeDigest;
		private Digest digest;
		private SPHINCS256Signer signer;
		private SecureRandom random;

		public SignatureSpi(Digest digest, ASN1ObjectIdentifier treeDigest, SPHINCS256Signer signer)
		{
			this.digest = digest;
			this.treeDigest = treeDigest;
			this.signer = signer;
		}

		public virtual void engineInitVerify(PublicKey publicKey)
		{
			if (publicKey is BCSphincs256PublicKey)
			{
				BCSphincs256PublicKey key = (BCSphincs256PublicKey)publicKey;
				if (!treeDigest.Equals(key.getTreeDigest()))
				{
					throw new InvalidKeyException("SPHINCS-256 signature for tree digest: " + key.getTreeDigest());
				}
				CipherParameters param = key.getKeyParams();

				digest.reset();
				signer.init(false, param);
			}
			else
			{
				throw new InvalidKeyException("unknown public key passed to SPHINCS-256");
			}
		}

		public virtual void engineInitSign(PrivateKey privateKey, SecureRandom random)
		{
			this.random = random;
			engineInitSign(privateKey);
		}

		public virtual void engineInitSign(PrivateKey privateKey)
		{
			if (privateKey is BCSphincs256PrivateKey)
			{
				BCSphincs256PrivateKey key = (BCSphincs256PrivateKey)privateKey;
				if (!treeDigest.Equals(key.getTreeDigest()))
				{
					throw new InvalidKeyException("SPHINCS-256 signature for tree digest: " + key.getTreeDigest());
				}

				CipherParameters param = key.getKeyParams();

				// random not required for SPHINCS.
	//            if (random != null)
	//            {
	//                param = new ParametersWithRandom(param, random);
	//            }

				digest.reset();
				signer.init(true, param);
			}
			else
			{
				throw new InvalidKeyException("unknown private key passed to SPHINCS-256");
			}
		}

		public virtual void engineUpdate(byte b)
		{
			digest.update(b);
		}

		public virtual void engineUpdate(byte[] b, int off, int len)
		{
			digest.update(b, off, len);
		}

		public virtual byte[] engineSign()
		{
			byte[] hash = new byte[digest.getDigestSize()];
			digest.doFinal(hash, 0);
			try
			{
				byte[] sig = signer.generateSignature(hash);

				return sig;
			}
			catch (Exception e)
			{
				throw new SignatureException(e.ToString());
			}
		}

		public virtual bool engineVerify(byte[] sigBytes)
		{
			byte[] hash = new byte[digest.getDigestSize()];
			digest.doFinal(hash, 0);

			return signer.verifySignature(hash, sigBytes);
		}

		public virtual void engineSetParameter(AlgorithmParameterSpec @params)
		{
			// TODO
			throw new UnsupportedOperationException("engineSetParameter unsupported");
		}

		/// @deprecated replaced with #engineSetParameter(java.security.spec.AlgorithmParameterSpec) 
		public virtual void engineSetParameter(string param, object value)
		{
			throw new UnsupportedOperationException("engineSetParameter unsupported");
		}

		/// <summary>
		/// @deprecated
		/// </summary>
		public virtual object engineGetParameter(string param)
		{
			throw new UnsupportedOperationException("engineSetParameter unsupported");
		}

		public class withSha512 : SignatureSpi
		{
			public withSha512() : base(new SHA512Digest(), org.bouncycastle.asn1.nist.NISTObjectIdentifiers_Fields.id_sha512_256, new SPHINCS256Signer(new SHA512tDigest(256), new SHA512Digest()))
			{
			}
		}

		public class withSha3_512 : SignatureSpi
		{
			public withSha3_512() : base(new SHA3Digest(512), org.bouncycastle.asn1.nist.NISTObjectIdentifiers_Fields.id_sha3_256, new SPHINCS256Signer(new SHA3Digest(256), new SHA3Digest(512)))
			{
			}
		}
	}

}