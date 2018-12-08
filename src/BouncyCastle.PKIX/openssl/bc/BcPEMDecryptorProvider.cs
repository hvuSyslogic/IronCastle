namespace org.bouncycastle.openssl.bc
{

	public class BcPEMDecryptorProvider : PEMDecryptorProvider
	{
		private readonly char[] password;

		public BcPEMDecryptorProvider(char[] password)
		{
			this.password = password;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.openssl.PEMDecryptor get(final String dekAlgName)
		public virtual PEMDecryptor get(string dekAlgName)
		{
			return new PEMDecryptorAnonymousInnerClass(this, dekAlgName);
		}

		public class PEMDecryptorAnonymousInnerClass : PEMDecryptor
		{
			private readonly BcPEMDecryptorProvider outerInstance;

			private string dekAlgName;

			public PEMDecryptorAnonymousInnerClass(BcPEMDecryptorProvider outerInstance, string dekAlgName)
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

				return PEMUtilities.crypt(false, keyBytes, outerInstance.password, dekAlgName, iv);
			}
		}
	}

}