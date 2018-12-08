using System;

namespace org.bouncycastle.pqc.jcajce.provider.rainbow
{

	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using Digest = org.bouncycastle.crypto.Digest;
	using SHA224Digest = org.bouncycastle.crypto.digests.SHA224Digest;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using SHA384Digest = org.bouncycastle.crypto.digests.SHA384Digest;
	using SHA512Digest = org.bouncycastle.crypto.digests.SHA512Digest;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using RainbowSigner = org.bouncycastle.pqc.crypto.rainbow.RainbowSigner;

	/// <summary>
	/// Rainbow Signature class, extending the jce SignatureSpi.
	/// </summary>
	public class SignatureSpi : java.security.SignatureSpi
	{
		private Digest digest;
		private RainbowSigner signer;
		private SecureRandom random;

		public SignatureSpi(Digest digest, RainbowSigner signer)
		{
			this.digest = digest;
			this.signer = signer;
		}

		public virtual void engineInitVerify(PublicKey publicKey)
		{
			CipherParameters param;
			param = RainbowKeysToParams.generatePublicKeyParameter(publicKey);

			digest.reset();
			signer.init(false, param);
		}

		public virtual void engineInitSign(PrivateKey privateKey, SecureRandom random)
		{
			this.random = random;
			engineInitSign(privateKey);
		}

		public virtual void engineInitSign(PrivateKey privateKey)
		{
			CipherParameters param;
			param = RainbowKeysToParams.generatePrivateKeyParameter(privateKey);

			if (random != null)
			{
				param = new ParametersWithRandom(param, random);
			}

			digest.reset();
			signer.init(true, param);

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


		public class withSha224 : SignatureSpi
		{
			public withSha224() : base(new SHA224Digest(), new RainbowSigner())
			{
			}
		}

		public class withSha256 : SignatureSpi
		{
			public withSha256() : base(new SHA256Digest(), new RainbowSigner())
			{
			}
		}

		public class withSha384 : SignatureSpi
		{
			public withSha384() : base(new SHA384Digest(), new RainbowSigner())
			{
			}
		}

		public class withSha512 : SignatureSpi
		{
			public withSha512() : base(new SHA512Digest(), new RainbowSigner())
			{
			}
		}
	}

}