using org.bouncycastle.crypto.signers;
using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.rsa
{

	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AsymmetricBlockCipher = org.bouncycastle.crypto.AsymmetricBlockCipher;
	using CryptoException = org.bouncycastle.crypto.CryptoException;
	using Digest = org.bouncycastle.crypto.Digest;
	using RSABlindedEngine = org.bouncycastle.crypto.engines.RSABlindedEngine;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using DigestFactory = org.bouncycastle.jcajce.provider.util.DigestFactory;
	using BCJcaJceHelper = org.bouncycastle.jcajce.util.BCJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;

	public class PSSSignatureSpi : SignatureSpi
	{
		private readonly JcaJceHelper helper = new BCJcaJceHelper();

		private AlgorithmParameters engineParams;
		private PSSParameterSpec paramSpec;
		private PSSParameterSpec originalSpec;
		private AsymmetricBlockCipher signer;
		private Digest contentDigest;
		private Digest mgfDigest;
		private int saltLength;
		private byte trailer;
		private bool isRaw;

		private PSSSigner pss;

		private byte getTrailer(int trailerField)
		{
			if (trailerField == 1)
			{
				return PSSSigner.TRAILER_IMPLICIT;
			}

			throw new IllegalArgumentException("unknown trailer field");
		}

		private void setupContentDigest()
		{
			if (isRaw)
			{
				this.contentDigest = new NullPssDigest(this, mgfDigest);
			}
			else
			{
				this.contentDigest = mgfDigest;
			}
		}

		// care - this constructor is actually used by outside organisations
		public PSSSignatureSpi(AsymmetricBlockCipher signer, PSSParameterSpec paramSpecArg) : this(signer, paramSpecArg, false)
		{
		}

		// care - this constructor is actually used by outside organisations
		public PSSSignatureSpi(AsymmetricBlockCipher signer, PSSParameterSpec baseParamSpec, bool isRaw)
		{
			this.signer = signer;
			this.originalSpec = baseParamSpec;

			if (baseParamSpec == null)
			{
				this.paramSpec = PSSParameterSpec.DEFAULT;
			}
			else
			{
				this.paramSpec = baseParamSpec;
			}

			this.mgfDigest = DigestFactory.getDigest(paramSpec.getDigestAlgorithm());
			this.saltLength = paramSpec.getSaltLength();
			this.trailer = getTrailer(paramSpec.getTrailerField());
			this.isRaw = isRaw;

			setupContentDigest();
		}

		public virtual void engineInitVerify(PublicKey publicKey)
		{
			if (!(publicKey is RSAPublicKey))
			{
				throw new InvalidKeyException("Supplied key is not a RSAPublicKey instance");
			}

			pss = new PSSSigner(signer, contentDigest, mgfDigest, saltLength, trailer);
			pss.init(false, RSAUtil.generatePublicKeyParameter((RSAPublicKey)publicKey));
		}

		public virtual void engineInitSign(PrivateKey privateKey, SecureRandom random)
		{
			if (!(privateKey is RSAPrivateKey))
			{
				throw new InvalidKeyException("Supplied key is not a RSAPrivateKey instance");
			}

			pss = new PSSSigner(signer, contentDigest, mgfDigest, saltLength, trailer);
			pss.init(true, new ParametersWithRandom(RSAUtil.generatePrivateKeyParameter((RSAPrivateKey)privateKey), random));
		}

		public virtual void engineInitSign(PrivateKey privateKey)
		{
			if (!(privateKey is RSAPrivateKey))
			{
				throw new InvalidKeyException("Supplied key is not a RSAPrivateKey instance");
			}

			pss = new PSSSigner(signer, contentDigest, mgfDigest, saltLength, trailer);
			pss.init(true, RSAUtil.generatePrivateKeyParameter((RSAPrivateKey)privateKey));
		}

		public virtual void engineUpdate(byte b)
		{
			pss.update(b);
		}

		public virtual void engineUpdate(byte[] b, int off, int len)
		{
			pss.update(b, off, len);
		}

		public virtual byte[] engineSign()
		{
			try
			{
				return pss.generateSignature();
			}
			catch (CryptoException e)
			{
				throw new SignatureException(e.Message);
			}
		}

		public virtual bool engineVerify(byte[] sigBytes)
		{
			return pss.verifySignature(sigBytes);
		}

		public virtual void engineSetParameter(AlgorithmParameterSpec @params)
		{
			if (@params is PSSParameterSpec)
			{
				PSSParameterSpec newParamSpec = (PSSParameterSpec)@params;

				if (originalSpec != null)
				{
					if (!DigestFactory.isSameDigest(originalSpec.getDigestAlgorithm(), newParamSpec.getDigestAlgorithm()))
					{
						throw new InvalidAlgorithmParameterException("parameter must be using " + originalSpec.getDigestAlgorithm());
					}
				}
				if (!newParamSpec.getMGFAlgorithm().equalsIgnoreCase("MGF1") && !newParamSpec.getMGFAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_mgf1.getId()))
				{
					throw new InvalidAlgorithmParameterException("unknown mask generation function specified");
				}

				if (!(newParamSpec.getMGFParameters() is MGF1ParameterSpec))
				{
					throw new InvalidAlgorithmParameterException("unknown MGF parameters");
				}

				MGF1ParameterSpec mgfParams = (MGF1ParameterSpec)newParamSpec.getMGFParameters();

				if (!DigestFactory.isSameDigest(mgfParams.getDigestAlgorithm(), newParamSpec.getDigestAlgorithm()))
				{
					throw new InvalidAlgorithmParameterException("digest algorithm for MGF should be the same as for PSS parameters.");
				}

				Digest newDigest = DigestFactory.getDigest(mgfParams.getDigestAlgorithm());

				if (newDigest == null)
				{
					throw new InvalidAlgorithmParameterException("no match on MGF digest algorithm: " + mgfParams.getDigestAlgorithm());
				}

				this.engineParams = null;
				this.paramSpec = newParamSpec;
				this.mgfDigest = newDigest;
				this.saltLength = paramSpec.getSaltLength();
				this.trailer = getTrailer(paramSpec.getTrailerField());

				setupContentDigest();
			}
			else
			{
				throw new InvalidAlgorithmParameterException("Only PSSParameterSpec supported");
			}
		}

		public virtual AlgorithmParameters engineGetParameters()
		{
			if (engineParams == null)
			{
				if (paramSpec != null)
				{
					try
					{
						engineParams = helper.createAlgorithmParameters("PSS");
						engineParams.init(paramSpec);
					}
					catch (Exception e)
					{
						throw new RuntimeException(e.ToString());
					}
				}
			}

			return engineParams;
		}

		/// @deprecated replaced with <a href="#engineSetParameter(java.security.spec.AlgorithmParameterSpec)">engineSetParameter(java.security.spec.AlgorithmParameterSpec)</a> 
		public virtual void engineSetParameter(string param, object value)
		{
			throw new UnsupportedOperationException("engineSetParameter unsupported");
		}

		public virtual object engineGetParameter(string param)
		{
			throw new UnsupportedOperationException("engineGetParameter unsupported");
		}

		public class nonePSS : PSSSignatureSpi
		{
			public nonePSS() : base(new RSABlindedEngine(), null, true)
			{
			}
		}

		public class PSSwithRSA : PSSSignatureSpi
		{
			public PSSwithRSA() : base(new RSABlindedEngine(), null)
			{
			}
		}

		public class SHA1withRSA : PSSSignatureSpi
		{
			public SHA1withRSA() : base(new RSABlindedEngine(), PSSParameterSpec.DEFAULT)
			{
			}
		}

		public class SHA224withRSA : PSSSignatureSpi
		{
			public SHA224withRSA() : base(new RSABlindedEngine(), new PSSParameterSpec("SHA-224", "MGF1", new MGF1ParameterSpec("SHA-224"), 28, 1))
			{
			}
		}

		public class SHA256withRSA : PSSSignatureSpi
		{
			public SHA256withRSA() : base(new RSABlindedEngine(), new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1))
			{
			}
		}

		public class SHA384withRSA : PSSSignatureSpi
		{
			public SHA384withRSA() : base(new RSABlindedEngine(), new PSSParameterSpec("SHA-384", "MGF1", new MGF1ParameterSpec("SHA-384"), 48, 1))
			{
			}
		}

		public class SHA512withRSA : PSSSignatureSpi
		{
			public SHA512withRSA() : base(new RSABlindedEngine(), new PSSParameterSpec("SHA-512", "MGF1", new MGF1ParameterSpec("SHA-512"), 64, 1))
			{
			}
		}

		public class SHA512_224withRSA : PSSSignatureSpi
		{
			public SHA512_224withRSA() : base(new RSABlindedEngine(), new PSSParameterSpec("SHA-512(224)", "MGF1", new MGF1ParameterSpec("SHA-512(224)"), 28, 1))
			{
			}
		}

		public class SHA512_256withRSA : PSSSignatureSpi
		{
			public SHA512_256withRSA() : base(new RSABlindedEngine(), new PSSParameterSpec("SHA-512(256)", "MGF1", new MGF1ParameterSpec("SHA-512(256)"), 32, 1))
			{
			}
		}

		public class SHA3_224withRSA : PSSSignatureSpi
		{
			public SHA3_224withRSA() : base(new RSABlindedEngine(), new PSSParameterSpec("SHA3-224", "MGF1", new MGF1ParameterSpec("SHA3-224"), 28, 1))
			{
			}
		}

		public class SHA3_256withRSA : PSSSignatureSpi
		{
			public SHA3_256withRSA() : base(new RSABlindedEngine(), new PSSParameterSpec("SHA3-256", "MGF1", new MGF1ParameterSpec("SHA3-256"), 32, 1))
			{
			}
		}

		public class SHA3_384withRSA : PSSSignatureSpi
		{
			public SHA3_384withRSA() : base(new RSABlindedEngine(), new PSSParameterSpec("SHA3-384", "MGF1", new MGF1ParameterSpec("SHA3-384"), 48, 1))
			{
			}
		}

		public class SHA3_512withRSA : PSSSignatureSpi
		{
			public SHA3_512withRSA() : base(new RSABlindedEngine(), new PSSParameterSpec("SHA3-512", "MGF1", new MGF1ParameterSpec("SHA3-512"), 64, 1))
			{
			}
		}

		public class NullPssDigest : Digest
		{
			private readonly PSSSignatureSpi outerInstance;

			internal ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			internal Digest baseDigest;
			internal bool oddTime = true;

			public NullPssDigest(PSSSignatureSpi outerInstance, Digest mgfDigest)
			{
				this.outerInstance = outerInstance;
				this.baseDigest = mgfDigest;
			}

			public virtual string getAlgorithmName()
			{
				return "NULL";
			}

			public virtual int getDigestSize()
			{
				return baseDigest.getDigestSize();
			}

			public virtual void update(byte @in)
			{
				bOut.write(@in);
			}

			public virtual void update(byte[] @in, int inOff, int len)
			{
				bOut.write(@in, inOff, len);
			}

			public virtual int doFinal(byte[] @out, int outOff)
			{
				byte[] res = bOut.toByteArray();

				if (oddTime)
				{
					JavaSystem.arraycopy(res, 0, @out, outOff, res.Length);
				}
				else
				{
					baseDigest.update(res, 0, res.Length);

					baseDigest.doFinal(@out, outOff);
				}

				reset();

				oddTime = !oddTime;

				return res.Length;
			}

			public virtual void reset()
			{
				bOut.reset();
				baseDigest.reset();
			}

			public virtual int getByteLength()
			{
				return 0;
			}
		}
	}

}