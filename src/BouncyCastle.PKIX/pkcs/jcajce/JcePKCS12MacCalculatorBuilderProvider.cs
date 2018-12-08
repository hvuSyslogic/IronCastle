using System;

namespace org.bouncycastle.pkcs.jcajce
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using PKCS12PBEParams = org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using PKCS12Key = org.bouncycastle.jcajce.PKCS12Key;
	using MacOutputStream = org.bouncycastle.jcajce.io.MacOutputStream;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
	using GenericKey = org.bouncycastle.@operator.GenericKey;
	using MacCalculator = org.bouncycastle.@operator.MacCalculator;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;

	public class JcePKCS12MacCalculatorBuilderProvider : PKCS12MacCalculatorBuilderProvider
	{
		private JcaJceHelper helper = new DefaultJcaJceHelper();

		public JcePKCS12MacCalculatorBuilderProvider()
		{
		}

		public virtual JcePKCS12MacCalculatorBuilderProvider setProvider(Provider provider)
		{
			this.helper = new ProviderJcaJceHelper(provider);

			return this;
		}

		public virtual JcePKCS12MacCalculatorBuilderProvider setProvider(string providerName)
		{
			this.helper = new NamedJcaJceHelper(providerName);

			return this;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.pkcs.PKCS12MacCalculatorBuilder get(final org.bouncycastle.asn1.x509.AlgorithmIdentifier algorithmIdentifier)
		public virtual PKCS12MacCalculatorBuilder get(AlgorithmIdentifier algorithmIdentifier)
		{
			return new PKCS12MacCalculatorBuilderAnonymousInnerClass(this, algorithmIdentifier);
		}

		public class PKCS12MacCalculatorBuilderAnonymousInnerClass : PKCS12MacCalculatorBuilder
		{
			private readonly JcePKCS12MacCalculatorBuilderProvider outerInstance;

			private AlgorithmIdentifier algorithmIdentifier;

			public PKCS12MacCalculatorBuilderAnonymousInnerClass(JcePKCS12MacCalculatorBuilderProvider outerInstance, AlgorithmIdentifier algorithmIdentifier)
			{
				this.outerInstance = outerInstance;
				this.algorithmIdentifier = algorithmIdentifier;
			}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.operator.MacCalculator build(final char[] password) throws org.bouncycastle.operator.OperatorCreationException
			public MacCalculator build(char[] password)
			{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.asn1.pkcs.PKCS12PBEParams pbeParams = org.bouncycastle.asn1.pkcs.PKCS12PBEParams.getInstance(algorithmIdentifier.getParameters());
				PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(algorithmIdentifier.getParameters());

				try
				{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.asn1.ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();
					ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final javax.crypto.Mac mac = helper.createMac(algorithm.getId());
					Mac mac = outerInstance.helper.createMac(algorithm.getId());

					PBEParameterSpec defParams = new PBEParameterSpec(pbeParams.getIV(), pbeParams.getIterations().intValue());

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final javax.crypto.SecretKey key = new org.bouncycastle.jcajce.PKCS12Key(password);
					SecretKey key = new PKCS12Key(password);

					mac.init(key, defParams);

					return new MacCalculatorAnonymousInnerClass(this, pbeParams, algorithm, mac, key);
				}
				catch (Exception e)
				{
					throw new OperatorCreationException("unable to create MAC calculator: " + e.Message, e);
				}
			}

			public class MacCalculatorAnonymousInnerClass : MacCalculator
			{
				private readonly PKCS12MacCalculatorBuilderAnonymousInnerClass outerInstance;

				private PKCS12PBEParams pbeParams;
				private ASN1ObjectIdentifier algorithm;
				private Mac mac;
				private SecretKey key;

				public MacCalculatorAnonymousInnerClass(PKCS12MacCalculatorBuilderAnonymousInnerClass outerInstance, PKCS12PBEParams pbeParams, ASN1ObjectIdentifier algorithm, Mac mac, SecretKey key)
				{
					this.outerInstance = outerInstance;
					this.pbeParams = pbeParams;
					this.algorithm = algorithm;
					this.mac = mac;
					this.key = key;
				}

				public AlgorithmIdentifier getAlgorithmIdentifier()
				{
					return new AlgorithmIdentifier(algorithm, pbeParams);
				}

				public OutputStream getOutputStream()
				{
					return new MacOutputStream(mac);
				}

				public byte[] getMac()
				{
					return mac.doFinal();
				}

				public GenericKey getKey()
				{
					return new GenericKey(getAlgorithmIdentifier(), key.getEncoded());
				}
			}

			public AlgorithmIdentifier getDigestAlgorithmIdentifier()
			{
				return new AlgorithmIdentifier(algorithmIdentifier.getAlgorithm(), DERNull.INSTANCE);
			}
		}
	}

}