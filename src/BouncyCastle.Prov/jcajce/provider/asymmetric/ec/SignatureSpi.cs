namespace org.bouncycastle.jcajce.provider.asymmetric.ec
{

	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using DSAExt = org.bouncycastle.crypto.DSAExt;
	using Digest = org.bouncycastle.crypto.Digest;
	using NullDigest = org.bouncycastle.crypto.digests.NullDigest;
	using RIPEMD160Digest = org.bouncycastle.crypto.digests.RIPEMD160Digest;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using DSAEncoding = org.bouncycastle.crypto.signers.DSAEncoding;
	using ECDSASigner = org.bouncycastle.crypto.signers.ECDSASigner;
	using ECNRSigner = org.bouncycastle.crypto.signers.ECNRSigner;
	using HMacDSAKCalculator = org.bouncycastle.crypto.signers.HMacDSAKCalculator;
	using PlainDSAEncoding = org.bouncycastle.crypto.signers.PlainDSAEncoding;
	using StandardDSAEncoding = org.bouncycastle.crypto.signers.StandardDSAEncoding;
	using DigestFactory = org.bouncycastle.crypto.util.DigestFactory;
	using DSABase = org.bouncycastle.jcajce.provider.asymmetric.util.DSABase;
	using ECUtil = org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;

	public class SignatureSpi : DSABase
	{
		public SignatureSpi(Digest digest, DSAExt signer, DSAEncoding encoding) : base(digest, signer, encoding)
		{
		}

		public virtual void engineInitVerify(PublicKey publicKey)
		{
			CipherParameters param = ECUtils.generatePublicKeyParameter(publicKey);

			digest.reset();
			signer.init(false, param);
		}

		public virtual void engineInitSign(PrivateKey privateKey)
		{
			CipherParameters param = ECUtil.generatePrivateKeyParameter(privateKey);

			digest.reset();

			if (appRandom != null)
			{
				signer.init(true, new ParametersWithRandom(param, appRandom));
			}
			else
			{
				signer.init(true, param);
			}
		}

		public class ecDSA : SignatureSpi
		{
			public ecDSA() : base(DigestFactory.createSHA1(), new ECDSASigner(), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecDetDSA : SignatureSpi
		{
			public ecDetDSA() : base(DigestFactory.createSHA1(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA1())), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecDSAnone : SignatureSpi
		{
			public ecDSAnone() : base(new NullDigest(), new ECDSASigner(), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecDSA224 : SignatureSpi
		{
			public ecDSA224() : base(DigestFactory.createSHA224(), new ECDSASigner(), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecDetDSA224 : SignatureSpi
		{
			public ecDetDSA224() : base(DigestFactory.createSHA224(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA224())), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecDSA256 : SignatureSpi
		{
			public ecDSA256() : base(DigestFactory.createSHA256(), new ECDSASigner(), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecDetDSA256 : SignatureSpi
		{
			public ecDetDSA256() : base(DigestFactory.createSHA256(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA256())), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecDSA384 : SignatureSpi
		{
			public ecDSA384() : base(DigestFactory.createSHA384(), new ECDSASigner(), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecDetDSA384 : SignatureSpi
		{
			public ecDetDSA384() : base(DigestFactory.createSHA384(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA384())), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecDSA512 : SignatureSpi
		{
			public ecDSA512() : base(DigestFactory.createSHA512(), new ECDSASigner(), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecDetDSA512 : SignatureSpi
		{
			public ecDetDSA512() : base(DigestFactory.createSHA512(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA512())), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecDSASha3_224 : SignatureSpi
		{
			public ecDSASha3_224() : base(DigestFactory.createSHA3_224(), new ECDSASigner(), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecDetDSASha3_224 : SignatureSpi
		{
			public ecDetDSASha3_224() : base(DigestFactory.createSHA3_224(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA3_224())), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecDSASha3_256 : SignatureSpi
		{
			public ecDSASha3_256() : base(DigestFactory.createSHA3_256(), new ECDSASigner(), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecDetDSASha3_256 : SignatureSpi
		{
			public ecDetDSASha3_256() : base(DigestFactory.createSHA3_256(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA3_256())), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecDSASha3_384 : SignatureSpi
		{
			public ecDSASha3_384() : base(DigestFactory.createSHA3_384(), new ECDSASigner(), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecDetDSASha3_384 : SignatureSpi
		{
			public ecDetDSASha3_384() : base(DigestFactory.createSHA3_384(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA3_384())), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecDSASha3_512 : SignatureSpi
		{
			public ecDSASha3_512() : base(DigestFactory.createSHA3_512(), new ECDSASigner(), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecDetDSASha3_512 : SignatureSpi
		{
			public ecDetDSASha3_512() : base(DigestFactory.createSHA3_512(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA3_512())), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecDSARipeMD160 : SignatureSpi
		{
			public ecDSARipeMD160() : base(new RIPEMD160Digest(), new ECDSASigner(), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecNR : SignatureSpi
		{
			public ecNR() : base(DigestFactory.createSHA1(), new ECNRSigner(), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecNR224 : SignatureSpi
		{
			public ecNR224() : base(DigestFactory.createSHA224(), new ECNRSigner(), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecNR256 : SignatureSpi
		{
			public ecNR256() : base(DigestFactory.createSHA256(), new ECNRSigner(), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecNR384 : SignatureSpi
		{
			public ecNR384() : base(DigestFactory.createSHA384(), new ECNRSigner(), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecNR512 : SignatureSpi
		{
			public ecNR512() : base(DigestFactory.createSHA512(), new ECNRSigner(), StandardDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecCVCDSA : SignatureSpi
		{
			public ecCVCDSA() : base(DigestFactory.createSHA1(), new ECDSASigner(), PlainDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecCVCDSA224 : SignatureSpi
		{
			public ecCVCDSA224() : base(DigestFactory.createSHA224(), new ECDSASigner(), PlainDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecCVCDSA256 : SignatureSpi
		{
			public ecCVCDSA256() : base(DigestFactory.createSHA256(), new ECDSASigner(), PlainDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecCVCDSA384 : SignatureSpi
		{
			public ecCVCDSA384() : base(DigestFactory.createSHA384(), new ECDSASigner(), PlainDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecCVCDSA512 : SignatureSpi
		{
			public ecCVCDSA512() : base(DigestFactory.createSHA512(), new ECDSASigner(), PlainDSAEncoding.INSTANCE)
			{
			}
		}

		public class ecPlainDSARP160 : SignatureSpi
		{
			public ecPlainDSARP160() : base(new RIPEMD160Digest(), new ECDSASigner(), PlainDSAEncoding.INSTANCE)
			{
			}
		}
	}

}