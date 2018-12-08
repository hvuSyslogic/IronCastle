using System;

namespace org.bouncycastle.openssl.jcajce
{

	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	public class JcePEMEncryptorBuilder
	{
		private readonly string algorithm;

		private JcaJceHelper helper = new DefaultJcaJceHelper();
		private SecureRandom random;

		public JcePEMEncryptorBuilder(string algorithm)
		{
			this.algorithm = algorithm;
		}

		public virtual JcePEMEncryptorBuilder setProvider(Provider provider)
		{
			this.helper = new ProviderJcaJceHelper(provider);

			return this;
		}

		public virtual JcePEMEncryptorBuilder setProvider(string providerName)
		{
			this.helper = new NamedJcaJceHelper(providerName);

			return this;
		}

		public virtual JcePEMEncryptorBuilder setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.openssl.PEMEncryptor build(final char[] password)
		public virtual PEMEncryptor build(char[] password)
		{
			if (random == null)
			{
				random = new SecureRandom();
			}

			int ivLength = algorithm.StartsWith("AES-", StringComparison.Ordinal) ? 16 : 8;

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] iv = new byte[ivLength];
			byte[] iv = new byte[ivLength];

			random.nextBytes(iv);

			return new PEMEncryptorAnonymousInnerClass(this, password, iv);
		}

		public class PEMEncryptorAnonymousInnerClass : PEMEncryptor
		{
			private readonly JcePEMEncryptorBuilder outerInstance;

			private char[] password;
			private byte[] iv;

			public PEMEncryptorAnonymousInnerClass(JcePEMEncryptorBuilder outerInstance, char[] password, byte[] iv)
			{
				this.outerInstance = outerInstance;
				this.password = password;
				this.iv = iv;
			}

			public string getAlgorithm()
			{
				return outerInstance.algorithm;
			}

			public byte[] getIV()
			{
				return iv;
			}

			public byte[] encrypt(byte[] encoding)
			{
				return PEMUtilities.crypt(true, outerInstance.helper, encoding, password, outerInstance.algorithm, iv);
			}
		}
	}

}