using System;

namespace org.bouncycastle.pqc.jcajce.provider.qtesla
{

	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using Digest = org.bouncycastle.crypto.Digest;
	using NullDigest = org.bouncycastle.crypto.digests.NullDigest;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using QTESLASecurityCategory = org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
	using QTESLASigner = org.bouncycastle.pqc.crypto.qtesla.QTESLASigner;

	public class SignatureSpi : Signature
	{
		public SignatureSpi(string algorithm) : base(algorithm)
		{
		}

		private Digest digest;
		private QTESLASigner signer;
		private SecureRandom random;

		public SignatureSpi(string sigName, Digest digest, QTESLASigner signer) : base(sigName)
		{

			this.digest = digest;
			this.signer = signer;
		}

		public virtual void engineInitVerify(PublicKey publicKey)
		{
			if (publicKey is BCqTESLAPublicKey)
			{
				CipherParameters param = ((BCqTESLAPublicKey)publicKey).getKeyParams();

				digest.reset();
				signer.init(false, param);
			}
			else
			{
				throw new InvalidKeyException("unknown public key passed to qTESLA");
			}
		}

		public virtual void engineInitSign(PrivateKey privateKey, SecureRandom random)
		{
			this.random = random;
			engineInitSign(privateKey);
		}

		public virtual void engineInitSign(PrivateKey privateKey)
		{
			if (privateKey is BCqTESLAPrivateKey)
			{
				CipherParameters param = ((BCqTESLAPrivateKey)privateKey).getKeyParams();

				if (random != null)
				{
					param = new ParametersWithRandom(param, random);
				}

				signer.init(true, param);
			}
			else
			{
				throw new InvalidKeyException("unknown private key passed to qTESLA");
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
			try
			{
				byte[] hash = DigestUtil.getDigestResult(digest);

				return signer.generateSignature(hash);
			}
			catch (Exception e)
			{
				if (e is IllegalStateException)
				{
					throw new SignatureException(e.Message);
				}
				throw new SignatureException(e.ToString());
			}
		}

		public virtual bool engineVerify(byte[] sigBytes)
		{
			byte[] hash = DigestUtil.getDigestResult(digest);

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

		public class qTESLA : SignatureSpi
		{
			public qTESLA() : base("qTESLA", new NullDigest(), new QTESLASigner())
			{
			}
		}

		public class HeuristicI : SignatureSpi
		{
			public HeuristicI() : base(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_I), new NullDigest(), new QTESLASigner())
			{
			}
		}

		public class HeuristicIIISize : SignatureSpi
		{
			public HeuristicIIISize() : base(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_III_SIZE), new NullDigest(), new QTESLASigner())
			{
			}
		}

		public class HeuristicIIISpeed : SignatureSpi
		{
			public HeuristicIIISpeed() : base(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_III_SPEED), new NullDigest(), new QTESLASigner())
			{
			}
		}

		public class ProvablySecureI : SignatureSpi
		{
			public ProvablySecureI() : base(QTESLASecurityCategory.getName(QTESLASecurityCategory.PROVABLY_SECURE_I), new NullDigest(), new QTESLASigner())
			{
			}
		}

		public class ProvablySecureIII : SignatureSpi
		{
			public ProvablySecureIII() : base(QTESLASecurityCategory.getName(QTESLASecurityCategory.PROVABLY_SECURE_III), new NullDigest(), new QTESLASigner())
			{
			}
		}
	}

}