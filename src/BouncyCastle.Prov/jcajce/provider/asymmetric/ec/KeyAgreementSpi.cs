using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.ec
{

	using X9IntegerConverter = org.bouncycastle.asn1.x9.X9IntegerConverter;
	using BasicAgreement = org.bouncycastle.crypto.BasicAgreement;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using DerivationFunction = org.bouncycastle.crypto.DerivationFunction;
	using ECDHBasicAgreement = org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
	using ECDHCBasicAgreement = org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
	using ECDHCUnifiedAgreement = org.bouncycastle.crypto.agreement.ECDHCUnifiedAgreement;
	using ECMQVBasicAgreement = org.bouncycastle.crypto.agreement.ECMQVBasicAgreement;
	using ConcatenationKDFGenerator = org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
	using RIPEMD160Digest = org.bouncycastle.crypto.digests.RIPEMD160Digest;
	using KDF2BytesGenerator = org.bouncycastle.crypto.generators.KDF2BytesGenerator;
	using ECDHUPrivateParameters = org.bouncycastle.crypto.@params.ECDHUPrivateParameters;
	using ECDHUPublicParameters = org.bouncycastle.crypto.@params.ECDHUPublicParameters;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using MQVPrivateParameters = org.bouncycastle.crypto.@params.MQVPrivateParameters;
	using MQVPublicParameters = org.bouncycastle.crypto.@params.MQVPublicParameters;
	using DigestFactory = org.bouncycastle.crypto.util.DigestFactory;
	using BaseAgreementSpi = org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi;
	using ECUtil = org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
	using DHUParameterSpec = org.bouncycastle.jcajce.spec.DHUParameterSpec;
	using MQVParameterSpec = org.bouncycastle.jcajce.spec.MQVParameterSpec;
	using UserKeyingMaterialSpec = org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
	using ECPrivateKey = org.bouncycastle.jce.interfaces.ECPrivateKey;
	using ECPublicKey = org.bouncycastle.jce.interfaces.ECPublicKey;
	using MQVPrivateKey = org.bouncycastle.jce.interfaces.MQVPrivateKey;
	using MQVPublicKey = org.bouncycastle.jce.interfaces.MQVPublicKey;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Diffie-Hellman key agreement using elliptic curve keys, ala IEEE P1363
	/// both the simple one, and the simple one with cofactors are supported.
	/// <para>
	/// Also, MQV key agreement per SEC-1
	/// </para>
	/// </summary>
	public class KeyAgreementSpi : BaseAgreementSpi
	{
		private static readonly X9IntegerConverter converter = new X9IntegerConverter();

		private new string kaAlgorithm;

		private ECDomainParameters parameters;
		private object agreement;

		private MQVParameterSpec mqvParameters;
		private DHUParameterSpec dheParameters;
		private byte[] result;

		public KeyAgreementSpi(string kaAlgorithm, BasicAgreement agreement, DerivationFunction kdf) : base(kaAlgorithm, kdf)
		{

			this.kaAlgorithm = kaAlgorithm;
			this.agreement = agreement;
		}

		public KeyAgreementSpi(string kaAlgorithm, ECDHCUnifiedAgreement agreement, DerivationFunction kdf) : base(kaAlgorithm, kdf)
		{

			this.kaAlgorithm = kaAlgorithm;
			this.agreement = agreement;
		}

		public virtual byte[] bigIntToBytes(BigInteger r)
		{
			return converter.integerToBytes(r, converter.getByteLength(parameters.getCurve()));
		}

		public override Key engineDoPhase(Key key, bool lastPhase)
		{
			if (parameters == null)
			{
				throw new IllegalStateException(kaAlgorithm + " not initialised.");
			}

			if (!lastPhase)
			{
				throw new IllegalStateException(kaAlgorithm + " can only be between two parties.");
			}

			CipherParameters pubKey;
			if (agreement is ECMQVBasicAgreement)
			{
				if (!(key is MQVPublicKey))
				{
					ECPublicKeyParameters staticKey = (ECPublicKeyParameters) ECUtils.generatePublicKeyParameter((PublicKey)key);
					ECPublicKeyParameters ephemKey = (ECPublicKeyParameters) ECUtils.generatePublicKeyParameter(mqvParameters.getOtherPartyEphemeralKey());

					pubKey = new MQVPublicParameters(staticKey, ephemKey);
				}
				else
				{
					MQVPublicKey mqvPubKey = (MQVPublicKey)key;
					ECPublicKeyParameters staticKey = (ECPublicKeyParameters) ECUtils.generatePublicKeyParameter(mqvPubKey.getStaticKey());
					ECPublicKeyParameters ephemKey = (ECPublicKeyParameters) ECUtils.generatePublicKeyParameter(mqvPubKey.getEphemeralKey());

					pubKey = new MQVPublicParameters(staticKey, ephemKey);
				}
			}
			else if (agreement is ECDHCUnifiedAgreement)
			{
				ECPublicKeyParameters staticKey = (ECPublicKeyParameters) ECUtils.generatePublicKeyParameter((PublicKey)key);
				ECPublicKeyParameters ephemKey = (ECPublicKeyParameters) ECUtils.generatePublicKeyParameter(dheParameters.getOtherPartyEphemeralKey());

				pubKey = new ECDHUPublicParameters(staticKey, ephemKey);
			}
			else
			{
				if (!(key is PublicKey))
				{
					throw new InvalidKeyException(kaAlgorithm + " key agreement requires " + getSimpleName(typeof(ECPublicKey)) + " for doPhase");
				}

				pubKey = ECUtils.generatePublicKeyParameter((PublicKey)key);
			}

			try
			{
				if (agreement is BasicAgreement)
				{
					result = bigIntToBytes(((BasicAgreement)agreement).calculateAgreement(pubKey));
				}
				else
				{
					result = ((ECDHCUnifiedAgreement)agreement).calculateAgreement(pubKey);
				}
			}
//JAVA TO C# CONVERTER WARNING: 'final' catch parameters are not available in C#:
//ORIGINAL LINE: catch (final Exception e)
			catch (Exception e)
			{
				throw new InvalidKeyExceptionAnonymousInnerClass(this, "calculation failed: " + e.getMessage(), e);
			}

			return null;
		}

		public class InvalidKeyExceptionAnonymousInnerClass : InvalidKeyException
		{
			private readonly KeyAgreementSpi outerInstance;

			private ception e;

			public InvalidKeyExceptionAnonymousInnerClass(KeyAgreementSpi outerInstance, string getMessage, ception e) : base(getMessage)
			{
				this.outerInstance = outerInstance;
				this.e = e;
			}

			public Exception getCause()
			{
				return e;
			}
		}

		public override void engineInit(Key key, AlgorithmParameterSpec @params, SecureRandom random)
		{
			if (@params != null && !(@params is MQVParameterSpec || @params is UserKeyingMaterialSpec || @params is DHUParameterSpec))
			{
				throw new InvalidAlgorithmParameterException("No algorithm parameters supported");
			}

			initFromKey(key, @params);
		}

		public override void engineInit(Key key, SecureRandom random)
		{
			try
			{
				initFromKey(key, null);
			}
			catch (InvalidAlgorithmParameterException e)
			{
				// this should never occur.
				throw new InvalidKeyException(e.Message);
			}
		}

		private void initFromKey(Key key, AlgorithmParameterSpec parameterSpec)
		{
			if (agreement is ECMQVBasicAgreement)
			{
				mqvParameters = null;
				if (!(key is MQVPrivateKey) && !(parameterSpec is MQVParameterSpec))
				{
					throw new InvalidAlgorithmParameterException(kaAlgorithm + " key agreement requires " + getSimpleName(typeof(MQVParameterSpec)) + " for initialisation");
				}

				ECPrivateKeyParameters staticPrivKey;
				ECPrivateKeyParameters ephemPrivKey;
				ECPublicKeyParameters ephemPubKey;
				if (key is MQVPrivateKey)
				{
					MQVPrivateKey mqvPrivKey = (MQVPrivateKey)key;
					staticPrivKey = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(mqvPrivKey.getStaticPrivateKey());
					ephemPrivKey = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(mqvPrivKey.getEphemeralPrivateKey());

					ephemPubKey = null;
					if (mqvPrivKey.getEphemeralPublicKey() != null)
					{
						ephemPubKey = (ECPublicKeyParameters) ECUtils.generatePublicKeyParameter(mqvPrivKey.getEphemeralPublicKey());
					}
				}
				else
				{
					MQVParameterSpec mqvParameterSpec = (MQVParameterSpec)parameterSpec;

					staticPrivKey = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter((PrivateKey)key);
					ephemPrivKey = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(mqvParameterSpec.getEphemeralPrivateKey());

					ephemPubKey = null;
					if (mqvParameterSpec.getEphemeralPublicKey() != null)
					{
						ephemPubKey = (ECPublicKeyParameters) ECUtils.generatePublicKeyParameter(mqvParameterSpec.getEphemeralPublicKey());
					}
					mqvParameters = mqvParameterSpec;
					ukmParameters = mqvParameterSpec.getUserKeyingMaterial();
				}

				MQVPrivateParameters localParams = new MQVPrivateParameters(staticPrivKey, ephemPrivKey, ephemPubKey);
				this.parameters = staticPrivKey.getParameters();

				// TODO Validate that all the keys are using the same parameters?

				((ECMQVBasicAgreement)agreement).init(localParams);
			}
			else if (parameterSpec is DHUParameterSpec)
			{
				if (!(agreement is ECDHCUnifiedAgreement))
				{
					throw new InvalidAlgorithmParameterException(kaAlgorithm + " key agreement cannot be used with " + getSimpleName(typeof(DHUParameterSpec)));
				}
				DHUParameterSpec dheParameterSpec = (DHUParameterSpec)parameterSpec;
				ECPrivateKeyParameters staticPrivKey;
				ECPrivateKeyParameters ephemPrivKey;
				ECPublicKeyParameters ephemPubKey;

				staticPrivKey = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter((PrivateKey)key);
				ephemPrivKey = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(dheParameterSpec.getEphemeralPrivateKey());

				ephemPubKey = null;
				if (dheParameterSpec.getEphemeralPublicKey() != null)
				{
					ephemPubKey = (ECPublicKeyParameters) ECUtils.generatePublicKeyParameter(dheParameterSpec.getEphemeralPublicKey());
				}
				dheParameters = dheParameterSpec;
				ukmParameters = dheParameterSpec.getUserKeyingMaterial();

				ECDHUPrivateParameters localParams = new ECDHUPrivateParameters(staticPrivKey, ephemPrivKey, ephemPubKey);
				this.parameters = staticPrivKey.getParameters();

				((ECDHCUnifiedAgreement)agreement).init(localParams);
			}
			else
			{
				if (!(key is PrivateKey))
				{
					throw new InvalidKeyException(kaAlgorithm + " key agreement requires " + getSimpleName(typeof(ECPrivateKey)) + " for initialisation");
				}
				if (kdf == null && parameterSpec is UserKeyingMaterialSpec)
				{
					throw new InvalidAlgorithmParameterException("no KDF specified for UserKeyingMaterialSpec");
				}
				ECPrivateKeyParameters privKey = (ECPrivateKeyParameters)ECUtil.generatePrivateKeyParameter((PrivateKey)key);
				this.parameters = privKey.getParameters();
				ukmParameters = (parameterSpec is UserKeyingMaterialSpec) ? ((UserKeyingMaterialSpec)parameterSpec).getUserKeyingMaterial() : null;
				((BasicAgreement)agreement).init(privKey);
			}
		}

		private static string getSimpleName(Class clazz)
		{
			string fullName = clazz.getName();

			return fullName.Substring(fullName.LastIndexOf('.') + 1);
		}

		public override byte[] calcSecret()
		{
			return Arrays.clone(result);
		}

		public class DH : KeyAgreementSpi
		{
			public DH() : base("ECDH", new ECDHBasicAgreement(), null)
			{
			}
		}

		public class DHC : KeyAgreementSpi
		{
			public DHC() : base("ECDHC", new ECDHCBasicAgreement(), null)
			{
			}
		}

		public class MQV : KeyAgreementSpi
		{
			public MQV() : base("ECMQV", new ECMQVBasicAgreement(), null)
			{
			}
		}

		public class DHUC : KeyAgreementSpi
		{
			public DHUC() : base("ECCDHU", new ECDHCUnifiedAgreement(), null)
			{
			}
		}

		public class DHwithSHA1KDF : KeyAgreementSpi
		{
			public DHwithSHA1KDF() : base("ECDHwithSHA1KDF", new ECDHBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA1()))
			{
			}
		}

		public class DHwithSHA1KDFAndSharedInfo : KeyAgreementSpi
		{
			public DHwithSHA1KDFAndSharedInfo() : base("ECDHwithSHA1KDF", new ECDHBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA1()))
			{
			}
		}

		public class CDHwithSHA1KDFAndSharedInfo : KeyAgreementSpi
		{
			public CDHwithSHA1KDFAndSharedInfo() : base("ECCDHwithSHA1KDF", new ECDHCBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA1()))
			{
			}
		}

		public class DHwithSHA224KDFAndSharedInfo : KeyAgreementSpi
		{
			public DHwithSHA224KDFAndSharedInfo() : base("ECDHwithSHA224KDF", new ECDHBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA224()))
			{
			}
		}

		public class CDHwithSHA224KDFAndSharedInfo : KeyAgreementSpi
		{
			public CDHwithSHA224KDFAndSharedInfo() : base("ECCDHwithSHA224KDF", new ECDHCBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA224()))
			{
			}
		}

		public class DHwithSHA256KDFAndSharedInfo : KeyAgreementSpi
		{
			public DHwithSHA256KDFAndSharedInfo() : base("ECDHwithSHA256KDF", new ECDHBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA256()))
			{
			}
		}

		public class CDHwithSHA256KDFAndSharedInfo : KeyAgreementSpi
		{
			public CDHwithSHA256KDFAndSharedInfo() : base("ECCDHwithSHA256KDF", new ECDHCBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA256()))
			{
			}
		}

		public class DHwithSHA384KDFAndSharedInfo : KeyAgreementSpi
		{
			public DHwithSHA384KDFAndSharedInfo() : base("ECDHwithSHA384KDF", new ECDHBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA384()))
			{
			}
		}

		public class CDHwithSHA384KDFAndSharedInfo : KeyAgreementSpi
		{
			public CDHwithSHA384KDFAndSharedInfo() : base("ECCDHwithSHA384KDF", new ECDHCBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA384()))
			{
			}
		}

		public class DHwithSHA512KDFAndSharedInfo : KeyAgreementSpi
		{
			public DHwithSHA512KDFAndSharedInfo() : base("ECDHwithSHA512KDF", new ECDHBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA512()))
			{
			}
		}

		public class CDHwithSHA512KDFAndSharedInfo : KeyAgreementSpi
		{
			public CDHwithSHA512KDFAndSharedInfo() : base("ECCDHwithSHA512KDF", new ECDHCBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA512()))
			{
			}
		}

		public class MQVwithSHA1KDFAndSharedInfo : KeyAgreementSpi
		{
			public MQVwithSHA1KDFAndSharedInfo() : base("ECMQVwithSHA1KDF", new ECMQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA1()))
			{
			}
		}

		public class MQVwithSHA224KDFAndSharedInfo : KeyAgreementSpi
		{
			public MQVwithSHA224KDFAndSharedInfo() : base("ECMQVwithSHA224KDF", new ECMQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA224()))
			{
			}
		}

		public class MQVwithSHA256KDFAndSharedInfo : KeyAgreementSpi
		{
			public MQVwithSHA256KDFAndSharedInfo() : base("ECMQVwithSHA256KDF", new ECMQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA256()))
			{
			}
		}

		public class MQVwithSHA384KDFAndSharedInfo : KeyAgreementSpi
		{
			public MQVwithSHA384KDFAndSharedInfo() : base("ECMQVwithSHA384KDF", new ECMQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA384()))
			{
			}
		}

		public class MQVwithSHA512KDFAndSharedInfo : KeyAgreementSpi
		{
			public MQVwithSHA512KDFAndSharedInfo() : base("ECMQVwithSHA512KDF", new ECMQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA512()))
			{
			}
		}

		public class DHwithSHA1CKDF : KeyAgreementSpi
		{
			public DHwithSHA1CKDF() : base("ECDHwithSHA1CKDF", new ECDHCBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA1()))
			{
			}
		}

		public class DHwithSHA256CKDF : KeyAgreementSpi
		{
			public DHwithSHA256CKDF() : base("ECDHwithSHA256CKDF", new ECDHCBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA256()))
			{
			}
		}

		public class DHwithSHA384CKDF : KeyAgreementSpi
		{
			public DHwithSHA384CKDF() : base("ECDHwithSHA384CKDF", new ECDHCBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA384()))
			{
			}
		}

		public class DHwithSHA512CKDF : KeyAgreementSpi
		{
			public DHwithSHA512CKDF() : base("ECDHwithSHA512CKDF", new ECDHCBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA512()))
			{
			}
		}

		public class MQVwithSHA1CKDF : KeyAgreementSpi
		{
			public MQVwithSHA1CKDF() : base("ECMQVwithSHA1CKDF", new ECMQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA1()))
			{
			}
		}

		public class MQVwithSHA224CKDF : KeyAgreementSpi
		{
			public MQVwithSHA224CKDF() : base("ECMQVwithSHA224CKDF", new ECMQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA224()))
			{
			}
		}

		public class MQVwithSHA256CKDF : KeyAgreementSpi
		{
			public MQVwithSHA256CKDF() : base("ECMQVwithSHA256CKDF", new ECMQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA256()))
			{
			}
		}

		public class MQVwithSHA384CKDF : KeyAgreementSpi
		{
			public MQVwithSHA384CKDF() : base("ECMQVwithSHA384CKDF", new ECMQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA384()))
			{
			}
		}

		public class MQVwithSHA512CKDF : KeyAgreementSpi
		{
			public MQVwithSHA512CKDF() : base("ECMQVwithSHA512CKDF", new ECMQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA512()))
			{
			}
		}

		public class MQVwithSHA1KDF : KeyAgreementSpi
		{
			public MQVwithSHA1KDF() : base("ECMQVwithSHA1KDF", new ECMQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA1()))
			{
			}
		}

		public class MQVwithSHA224KDF : KeyAgreementSpi
		{
			public MQVwithSHA224KDF() : base("ECMQVwithSHA224KDF", new ECMQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA224()))
			{
			}
		}

		public class MQVwithSHA256KDF : KeyAgreementSpi
		{
			public MQVwithSHA256KDF() : base("ECMQVwithSHA256KDF", new ECMQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA256()))
			{
			}
		}

		public class MQVwithSHA384KDF : KeyAgreementSpi
		{
			public MQVwithSHA384KDF() : base("ECMQVwithSHA384KDF", new ECMQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA384()))
			{
			}
		}

		public class MQVwithSHA512KDF : KeyAgreementSpi
		{
			public MQVwithSHA512KDF() : base("ECMQVwithSHA512KDF", new ECMQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA512()))
			{
			}
		}

		public class DHUwithSHA1CKDF : KeyAgreementSpi
		{
			public DHUwithSHA1CKDF() : base("ECCDHUwithSHA1CKDF", new ECDHCUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA1()))
			{
			}
		}

		public class DHUwithSHA224CKDF : KeyAgreementSpi
		{
			public DHUwithSHA224CKDF() : base("ECCDHUwithSHA224CKDF", new ECDHCUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA224()))
			{
			}
		}

		public class DHUwithSHA256CKDF : KeyAgreementSpi
		{
			public DHUwithSHA256CKDF() : base("ECCDHUwithSHA256CKDF", new ECDHCUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA256()))
			{
			}
		}

		public class DHUwithSHA384CKDF : KeyAgreementSpi
		{
			public DHUwithSHA384CKDF() : base("ECCDHUwithSHA384CKDF", new ECDHCUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA384()))
			{
			}
		}

		public class DHUwithSHA512CKDF : KeyAgreementSpi
		{
			public DHUwithSHA512CKDF() : base("ECCDHUwithSHA512CKDF", new ECDHCUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA512()))
			{
			}
		}

		public class DHUwithSHA1KDF : KeyAgreementSpi
		{
			public DHUwithSHA1KDF() : base("ECCDHUwithSHA1KDF", new ECDHCUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA1()))
			{
			}
		}

		public class DHUwithSHA224KDF : KeyAgreementSpi
		{
			public DHUwithSHA224KDF() : base("ECCDHUwithSHA224KDF", new ECDHCUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA224()))
			{
			}
		}

		public class DHUwithSHA256KDF : KeyAgreementSpi
		{
			public DHUwithSHA256KDF() : base("ECCDHUwithSHA256KDF", new ECDHCUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA256()))
			{
			}
		}

		public class DHUwithSHA384KDF : KeyAgreementSpi
		{
			public DHUwithSHA384KDF() : base("ECCDHUwithSHA384KDF", new ECDHCUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA384()))
			{
			}
		}

		public class DHUwithSHA512KDF : KeyAgreementSpi
		{
			public DHUwithSHA512KDF() : base("ECCDHUwithSHA512KDF", new ECDHCUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA512()))
			{
			}
		}

		/// <summary>
		/// KeyAgreement according to BSI TR-03111 chapter 4.3.1
		/// </summary>
		   public class ECKAEGwithSHA1KDF : KeyAgreementSpi
		   {
			   public ECKAEGwithSHA1KDF() : base("ECKAEGwithSHA1KDF", new ECDHBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA1()))
			   {
			   }
		   }

		/// <summary>
		/// KeyAgreement according to BSI TR-03111 chapter 4.3.1
		/// </summary>
		   public class ECKAEGwithRIPEMD160KDF : KeyAgreementSpi
		   {
			   public ECKAEGwithRIPEMD160KDF() : base("ECKAEGwithRIPEMD160KDF", new ECDHBasicAgreement(), new KDF2BytesGenerator(new RIPEMD160Digest()))
			   {
			   }
		   }

		/// <summary>
		/// KeyAgreement according to BSI TR-03111 chapter 4.3.1
		/// </summary>
		   public class ECKAEGwithSHA224KDF : KeyAgreementSpi
		   {
			   public ECKAEGwithSHA224KDF() : base("ECKAEGwithSHA224KDF", new ECDHBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA224()))
			   {
			   }
		   }

		/// <summary>
		/// KeyAgreement according to BSI TR-03111 chapter 4.3.1
		/// </summary>
		public class ECKAEGwithSHA256KDF : KeyAgreementSpi
		{
			public ECKAEGwithSHA256KDF() : base("ECKAEGwithSHA256KDF", new ECDHBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA256()))
			{
			}
		}

		/// <summary>
		/// KeyAgreement according to BSI TR-03111 chapter 4.3.1
		/// </summary>
		public class ECKAEGwithSHA384KDF : KeyAgreementSpi
		{
			public ECKAEGwithSHA384KDF() : base("ECKAEGwithSHA384KDF", new ECDHBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA384()))
			{
			}
		}

		/// <summary>
		/// KeyAgreement according to BSI TR-03111 chapter 4.3.1
		/// </summary>
		public class ECKAEGwithSHA512KDF : KeyAgreementSpi
		{
			public ECKAEGwithSHA512KDF() : base("ECKAEGwithSHA512KDF", new ECDHBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA512()))
			{
			}
		}
	}

}