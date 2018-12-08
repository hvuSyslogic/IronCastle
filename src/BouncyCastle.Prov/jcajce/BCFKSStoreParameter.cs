namespace org.bouncycastle.jcajce
{

	using PBKDFConfig = org.bouncycastle.crypto.util.PBKDFConfig;

	/// <summary>
	/// LoadStoreParameter to allow configuring of the PBKDF used to generate encryption keys for
	/// use in the keystore. </summary>
	/// @deprecated This class does not support configuration on creation, use BCFKSLoadStoreParameter for best results. 
	public class BCFKSStoreParameter : KeyStore.LoadStoreParameter
	{
		private readonly KeyStore.ProtectionParameter protectionParameter;
		private readonly PBKDFConfig storeConfig;

		private OutputStream @out;

		public BCFKSStoreParameter(OutputStream @out, PBKDFConfig storeConfig, char[] password) : this(@out, storeConfig, new KeyStore.PasswordProtection(password))
		{
		}

		public BCFKSStoreParameter(OutputStream @out, PBKDFConfig storeConfig, KeyStore.ProtectionParameter protectionParameter)
		{
			this.@out = @out;
			this.storeConfig = storeConfig;
			this.protectionParameter = protectionParameter;
		}

		public virtual KeyStore.ProtectionParameter getProtectionParameter()
		{
			return protectionParameter;
		}

		public virtual OutputStream getOutputStream()
		{
			return @out;
		}

		/// <summary>
		/// Return the PBKDF used for generating the HMAC and store encryption keys.
		/// </summary>
		/// <returns> the PBKDF to use for deriving HMAC and store encryption keys. </returns>
		public virtual PBKDFConfig getStorePBKDFConfig()
		{
			return storeConfig;
		}
	}

}