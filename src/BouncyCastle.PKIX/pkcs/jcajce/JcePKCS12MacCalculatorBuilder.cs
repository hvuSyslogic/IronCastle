using System;

namespace org.bouncycastle.pkcs.jcajce
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
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

	public class JcePKCS12MacCalculatorBuilder : PKCS12MacCalculatorBuilder
	{
		private JcaJceHelper helper = new DefaultJcaJceHelper();
		private ASN1ObjectIdentifier algorithm;

		private SecureRandom random;
		private int saltLength;
		private int iterationCount = 1024;

		public JcePKCS12MacCalculatorBuilder() : this(org.bouncycastle.asn1.oiw.OIWObjectIdentifiers_Fields.idSHA1)
		{
		}

		public JcePKCS12MacCalculatorBuilder(ASN1ObjectIdentifier hashAlgorithm)
		{
			this.algorithm = hashAlgorithm;
		}

		public virtual JcePKCS12MacCalculatorBuilder setProvider(Provider provider)
		{
			this.helper = new ProviderJcaJceHelper(provider);

			return this;
		}

		public virtual JcePKCS12MacCalculatorBuilder setProvider(string providerName)
		{
			this.helper = new NamedJcaJceHelper(providerName);

			return this;
		}

		public virtual JcePKCS12MacCalculatorBuilder setIterationCount(int iterationCount)
		{
			this.iterationCount = iterationCount;

			return this;
		}

		public virtual AlgorithmIdentifier getDigestAlgorithmIdentifier()
		{
			return new AlgorithmIdentifier(algorithm, DERNull.INSTANCE);
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.operator.MacCalculator build(final char[] password) throws org.bouncycastle.operator.OperatorCreationException
		public virtual MacCalculator build(char[] password)
		{
			if (random == null)
			{
				random = new SecureRandom();
			}

			try
			{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final javax.crypto.Mac mac = helper.createMac(algorithm.getId());
				Mac mac = helper.createMac(algorithm.getId());

				saltLength = mac.getMacLength();
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] salt = new byte[saltLength];
				byte[] salt = new byte[saltLength];

				random.nextBytes(salt);

				PBEParameterSpec defParams = new PBEParameterSpec(salt, iterationCount);
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final javax.crypto.SecretKey key = new org.bouncycastle.jcajce.PKCS12Key(password);
				SecretKey key = new PKCS12Key(password);

				mac.init(key, defParams);

				return new MacCalculatorAnonymousInnerClass(this, mac, salt, key);
			}
			catch (Exception e)
			{
				throw new OperatorCreationException("unable to create MAC calculator: " + e.Message, e);
			}
		}

		public class MacCalculatorAnonymousInnerClass : MacCalculator
		{
			private readonly JcePKCS12MacCalculatorBuilder outerInstance;

			private Mac mac;
			private byte[] salt;
			private SecretKey key;

			public MacCalculatorAnonymousInnerClass(JcePKCS12MacCalculatorBuilder outerInstance, Mac mac, byte[] salt, SecretKey key)
			{
				this.outerInstance = outerInstance;
				this.mac = mac;
				this.salt = salt;
				this.key = key;
			}

			public AlgorithmIdentifier getAlgorithmIdentifier()
			{
				return new AlgorithmIdentifier(outerInstance.algorithm, new PKCS12PBEParams(salt, outerInstance.iterationCount));
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
	}

}