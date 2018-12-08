using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.dsa
{

	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using X509ObjectIdentifiers = org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using DSAExt = org.bouncycastle.crypto.DSAExt;
	using Digest = org.bouncycastle.crypto.Digest;
	using NullDigest = org.bouncycastle.crypto.digests.NullDigest;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using DSAEncoding = org.bouncycastle.crypto.signers.DSAEncoding;
	using HMacDSAKCalculator = org.bouncycastle.crypto.signers.HMacDSAKCalculator;
	using StandardDSAEncoding = org.bouncycastle.crypto.signers.StandardDSAEncoding;
	using DigestFactory = org.bouncycastle.crypto.util.DigestFactory;

	public class DSASigner : SignatureSpi, PKCSObjectIdentifiers, X509ObjectIdentifiers
	{
		private Digest digest;
		private DSAExt signer;
		private DSAEncoding encoding = StandardDSAEncoding.INSTANCE;
		private SecureRandom random;

		public DSASigner(Digest digest, DSAExt signer)
		{
			this.digest = digest;
			this.signer = signer;
		}

		public virtual void engineInitVerify(PublicKey publicKey)
		{
			CipherParameters param = DSAUtil.generatePublicKeyParameter(publicKey);

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
			CipherParameters param = DSAUtil.generatePrivateKeyParameter(privateKey);

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
				BigInteger[] sig = signer.generateSignature(hash);

				return encoding.encode(signer.getOrder(), sig[0], sig[1]);
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

			BigInteger[] sig;

			try
			{
				sig = encoding.decode(signer.getOrder(), sigBytes);
			}
			catch (Exception)
			{
				throw new SignatureException("error decoding signature bytes.");
			}

			return signer.verifySignature(hash, sig[0], sig[1]);
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
			throw new UnsupportedOperationException("engineGetParameter unsupported");
		}

		public class stdDSA : DSASigner
		{
			public stdDSA() : base(DigestFactory.createSHA1(), new org.bouncycastle.crypto.signers.DSASigner())
			{
			}
		}

		public class detDSA : DSASigner
		{
			public detDSA() : base(DigestFactory.createSHA1(), new org.bouncycastle.crypto.signers.DSASigner(new HMacDSAKCalculator(DigestFactory.createSHA1())))
			{
			}
		}

		public class dsa224 : DSASigner
		{
			public dsa224() : base(DigestFactory.createSHA224(), new org.bouncycastle.crypto.signers.DSASigner())
			{
			}
		}

		public class detDSA224 : DSASigner
		{
			public detDSA224() : base(DigestFactory.createSHA224(), new org.bouncycastle.crypto.signers.DSASigner(new HMacDSAKCalculator(DigestFactory.createSHA224())))
			{
			}
		}

		public class dsa256 : DSASigner
		{
			public dsa256() : base(DigestFactory.createSHA256(), new org.bouncycastle.crypto.signers.DSASigner())
			{
			}
		}

		public class detDSA256 : DSASigner
		{
			public detDSA256() : base(DigestFactory.createSHA256(), new org.bouncycastle.crypto.signers.DSASigner(new HMacDSAKCalculator(DigestFactory.createSHA256())))
			{
			}
		}

		public class dsa384 : DSASigner
		{
			public dsa384() : base(DigestFactory.createSHA384(), new org.bouncycastle.crypto.signers.DSASigner())
			{
			}
		}

		public class detDSA384 : DSASigner
		{
			public detDSA384() : base(DigestFactory.createSHA384(), new org.bouncycastle.crypto.signers.DSASigner(new HMacDSAKCalculator(DigestFactory.createSHA384())))
			{
			}
		}

		public class dsa512 : DSASigner
		{
			public dsa512() : base(DigestFactory.createSHA512(), new org.bouncycastle.crypto.signers.DSASigner())
			{
			}
		}

		public class detDSA512 : DSASigner
		{
			public detDSA512() : base(DigestFactory.createSHA512(), new org.bouncycastle.crypto.signers.DSASigner(new HMacDSAKCalculator(DigestFactory.createSHA512())))
			{
			}
		}

		public class dsaSha3_224 : DSASigner
		{
			public dsaSha3_224() : base(DigestFactory.createSHA3_224(), new org.bouncycastle.crypto.signers.DSASigner())
			{
			}
		}

		public class detDSASha3_224 : DSASigner
		{
			public detDSASha3_224() : base(DigestFactory.createSHA3_224(), new org.bouncycastle.crypto.signers.DSASigner(new HMacDSAKCalculator(DigestFactory.createSHA3_224())))
			{
			}
		}

		public class dsaSha3_256 : DSASigner
		{
			public dsaSha3_256() : base(DigestFactory.createSHA3_256(), new org.bouncycastle.crypto.signers.DSASigner())
			{
			}
		}

		public class detDSASha3_256 : DSASigner
		{
			public detDSASha3_256() : base(DigestFactory.createSHA3_256(), new org.bouncycastle.crypto.signers.DSASigner(new HMacDSAKCalculator(DigestFactory.createSHA3_256())))
			{
			}
		}

		public class dsaSha3_384 : DSASigner
		{
			public dsaSha3_384() : base(DigestFactory.createSHA3_384(), new org.bouncycastle.crypto.signers.DSASigner())
			{
			}
		}

		public class detDSASha3_384 : DSASigner
		{
			public detDSASha3_384() : base(DigestFactory.createSHA3_384(), new org.bouncycastle.crypto.signers.DSASigner(new HMacDSAKCalculator(DigestFactory.createSHA3_384())))
			{
			}
		}

		public class dsaSha3_512 : DSASigner
		{
			public dsaSha3_512() : base(DigestFactory.createSHA3_512(), new org.bouncycastle.crypto.signers.DSASigner())
			{
			}
		}

		public class detDSASha3_512 : DSASigner
		{
			public detDSASha3_512() : base(DigestFactory.createSHA3_512(), new org.bouncycastle.crypto.signers.DSASigner(new HMacDSAKCalculator(DigestFactory.createSHA3_512())))
			{
			}
		}

		public class noneDSA : DSASigner
		{
			public noneDSA() : base(new NullDigest(), new org.bouncycastle.crypto.signers.DSASigner())
			{
			}
		}
	}

}