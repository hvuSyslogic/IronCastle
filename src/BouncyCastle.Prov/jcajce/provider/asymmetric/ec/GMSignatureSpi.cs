using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.ec
{

	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using CryptoException = org.bouncycastle.crypto.CryptoException;
	using ParametersWithID = org.bouncycastle.crypto.@params.ParametersWithID;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using SM2Signer = org.bouncycastle.crypto.signers.SM2Signer;
	using ECUtil = org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
	using SM2ParameterSpec = org.bouncycastle.jcajce.spec.SM2ParameterSpec;
	using BCJcaJceHelper = org.bouncycastle.jcajce.util.BCJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;

	public class GMSignatureSpi : java.security.SignatureSpi
	{
		private readonly JcaJceHelper helper = new BCJcaJceHelper();

		private AlgorithmParameters engineParams;
		private SM2ParameterSpec paramSpec;

		private readonly SM2Signer signer;

		public GMSignatureSpi(SM2Signer signer)
		{
			this.signer = signer;
		}

		public virtual void engineInitVerify(PublicKey publicKey)
		{
			CipherParameters param = ECUtils.generatePublicKeyParameter(publicKey);

			if (paramSpec != null)
			{
				param = new ParametersWithID(param, paramSpec.getID());
			}

			signer.init(false, param);
		}

		public virtual void engineInitSign(PrivateKey privateKey)
		{
			CipherParameters param = ECUtil.generatePrivateKeyParameter(privateKey);

			if (appRandom != null)
			{
				param = new ParametersWithRandom(param, appRandom);
			}

			if (paramSpec != null)
			{
				signer.init(true, new ParametersWithID(param, paramSpec.getID()));
			}
			else
			{
				signer.init(true, param);
			}
		}

		public virtual void engineUpdate(byte b)
		{
			signer.update(b);
		}

		public virtual void engineUpdate(byte[] bytes, int off, int length)
		{
			signer.update(bytes, off, length);
		}

		public virtual byte[] engineSign()
		{
			try
			{
				return signer.generateSignature();
			}
			catch (CryptoException e)
			{
				throw new SignatureException("unable to create signature: " + e.Message);
			}
		}

		public virtual bool engineVerify(byte[] bytes)
		{
			return signer.verifySignature(bytes);
		}

		public virtual void engineSetParameter(AlgorithmParameterSpec @params)
		{
			if (@params is SM2ParameterSpec)
			{
				paramSpec = (SM2ParameterSpec)@params;
			}
			else
			{
				throw new InvalidAlgorithmParameterException("only SM2ParameterSpec supported");
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

		public virtual void engineSetParameter(string param, object value)
		{
			throw new UnsupportedOperationException("engineSetParameter unsupported");
		}

		public virtual object engineGetParameter(string param)
		{
			throw new UnsupportedOperationException("engineGetParameter unsupported");
		}

		public class sm3WithSM2 : GMSignatureSpi
		{
			public sm3WithSM2() : base(new SM2Signer())
			{
			}
		}
	}
}