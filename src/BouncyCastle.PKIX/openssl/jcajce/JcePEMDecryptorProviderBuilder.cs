namespace org.bouncycastle.openssl.jcajce
{

	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	public class JcePEMDecryptorProviderBuilder
	{
		private JcaJceHelper helper = new DefaultJcaJceHelper();

		public virtual JcePEMDecryptorProviderBuilder setProvider(Provider provider)
		{
			this.helper = new ProviderJcaJceHelper(provider);

			return this;
		}

		public virtual JcePEMDecryptorProviderBuilder setProvider(string providerName)
		{
			this.helper = new NamedJcaJceHelper(providerName);

			return this;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.openssl.PEMDecryptorProvider build(final char[] password)
		public virtual PEMDecryptorProvider build(char[] password)
		{
			return new PEMDecryptorProviderAnonymousInnerClass(this, password);
		}

		public class PEMDecryptorProviderAnonymousInnerClass : PEMDecryptorProvider
		{
			private readonly JcePEMDecryptorProviderBuilder outerInstance;

			private char[] password;

			public PEMDecryptorProviderAnonymousInnerClass(JcePEMDecryptorProviderBuilder outerInstance, char[] password)
			{
				this.outerInstance = outerInstance;
				this.password = password;
			}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.openssl.PEMDecryptor get(final String dekAlgName)
			public PEMDecryptor get(string dekAlgName)
			{
				return new PEMDecryptorAnonymousInnerClass(this, dekAlgName);
			}

			public class PEMDecryptorAnonymousInnerClass : PEMDecryptor
			{
				private readonly PEMDecryptorProviderAnonymousInnerClass outerInstance;

				private string dekAlgName;

				public PEMDecryptorAnonymousInnerClass(PEMDecryptorProviderAnonymousInnerClass outerInstance, string dekAlgName)
				{
					this.outerInstance = outerInstance;
					this.dekAlgName = dekAlgName;
				}

				public byte[] decrypt(byte[] keyBytes, byte[] iv)
				{
					if (outerInstance.password == null)
					{
						throw new PasswordException("Password is null, but a password is required");
					}

					return PEMUtilities.crypt(false, outerInstance.outerInstance.helper, keyBytes, outerInstance.password, dekAlgName, iv);
				}
			}
		}
	}

}