namespace org.bouncycastle.jcajce
{

	using PBKDF2Config = org.bouncycastle.crypto.util.PBKDF2Config;
	using PBKDFConfig = org.bouncycastle.crypto.util.PBKDFConfig;

	/// <summary>
	/// LoadStoreParameter to allow configuring of the PBKDF used to generate encryption keys for
	/// use in the keystore.
	/// </summary>
	public class BCFKSLoadStoreParameter : BCLoadStoreParameter
	{

		public enum EncryptionAlgorithm
		{
			AES256_CCM,
			AES256_KWP
		}

		public enum MacAlgorithm
		{
			HmacSHA512,
			HmacSHA3_512
		}

		public class Builder
		{
			internal readonly OutputStream @out;
			internal readonly InputStream @in;
			internal readonly KeyStore.ProtectionParameter protectionParameter;

			internal PBKDFConfig storeConfig = new PBKDF2Config.Builder().withIterationCount(16384).withSaltLength(64).withPRF(PBKDF2Config.PRF_SHA512).build();
			internal EncryptionAlgorithm encAlg = EncryptionAlgorithm.AES256_CCM;
			internal MacAlgorithm macAlg = MacAlgorithm.HmacSHA512;

			/// <summary>
			/// Base constructor for creating a LoadStoreParameter for initializing a key store.
			/// </summary>
			public Builder() : this((OutputStream)null, (KeyStore.ProtectionParameter)null)
			{
			}

			/// <summary>
			/// Base constructor for storing to an OutputStream using a password.
			/// </summary>
			/// <param name="out"> OutputStream to write KeyStore to. </param>
			/// <param name="password"> the password to use to protect the KeyStore. </param>
			public Builder(OutputStream @out, char[] password) : this(@out, new KeyStore.PasswordProtection(password))
			{
			}

			/// <summary>
			/// Base constructor for storing to an OutputStream using a protection parameter.
			/// </summary>
			/// <param name="out"> OutputStream to write KeyStore to. </param>
			/// <param name="protectionParameter"> the protection parameter to use to protect the KeyStore. </param>
			public Builder(OutputStream @out, KeyStore.ProtectionParameter protectionParameter)
			{
				this.@in = null;
				this.@out = @out;
				this.protectionParameter = protectionParameter;
			}

			/// <summary>
			/// Base constructor for reading a KeyStore from an InputStream using a password.
			/// </summary>
			/// <param name="in"> InputStream to read the KeyStore from. </param>
			/// <param name="password"> the password used to protect the KeyStore. </param>
			public Builder(InputStream @in, char[] password) : this(@in, new KeyStore.PasswordProtection(password))
			{
			}

			/// <summary>
			/// Base constructor for reading a KeyStore from an InputStream using a password.
			/// </summary>
			/// <param name="in"> InputStream to read the KeyStore from. </param>
			/// <param name="protectionParameter">  the protection parameter used to protect the KeyStore. </param>
			public Builder(InputStream @in, KeyStore.ProtectionParameter protectionParameter)
			{
				this.@in = @in;
				this.@out = null;
				this.protectionParameter = protectionParameter;
			}

			/// <summary>
			/// Configure the PBKDF to use for protecting the KeyStore.
			/// </summary>
			/// <param name="storeConfig"> the PBKDF config to use for protecting the KeyStore. </param>
			/// <returns> the current Builder instance. </returns>
			public virtual Builder withStorePBKDFConfig(PBKDFConfig storeConfig)
			{
				this.storeConfig = storeConfig;
				return this;
			}

			/// <summary>
			/// Configure the encryption algorithm to use for protecting the KeyStore and its keys.
			/// </summary>
			/// <param name="encAlg"> the PBKDF config to use for protecting the KeyStore and its keys. </param>
			/// <returns> the current Builder instance. </returns>
			public virtual Builder withStoreEncryptionAlgorithm(EncryptionAlgorithm encAlg)
			{
				this.encAlg = encAlg;
				return this;
			}

			/// <summary>
			/// Configure the MAC algorithm to use for protecting the KeyStore.
			/// </summary>
			/// <param name="macAlg"> the PBKDF config to use for protecting the KeyStore. </param>
			/// <returns> the current Builder instance. </returns>
			public virtual Builder withStoreMacAlgorithm(MacAlgorithm macAlg)
			{
				this.macAlg = macAlg;
				return this;
			}

			/// <summary>
			/// Build and return a BCFKSLoadStoreParameter.
			/// </summary>
			/// <returns> a new BCFKSLoadStoreParameter. </returns>
			public virtual BCFKSLoadStoreParameter build()
			{
				return new BCFKSLoadStoreParameter(@in, @out, storeConfig, protectionParameter, encAlg, macAlg);
			}
		}

		private readonly PBKDFConfig storeConfig;
		private readonly EncryptionAlgorithm encAlg;
		private readonly MacAlgorithm macAlg;

		private BCFKSLoadStoreParameter(InputStream @in, OutputStream @out, PBKDFConfig storeConfig, KeyStore.ProtectionParameter protectionParameter, EncryptionAlgorithm encAlg, MacAlgorithm macAlg) : base(@in, @out, protectionParameter)
		{

			this.storeConfig = storeConfig;
			this.encAlg = encAlg;
			this.macAlg = macAlg;
		}

		/// <summary>
		/// Return the PBKDF used for generating the HMAC and store encryption keys.
		/// </summary>
		/// <returns> the PBKDF to use for deriving HMAC and store encryption keys. </returns>
		public virtual PBKDFConfig getStorePBKDFConfig()
		{
			return storeConfig;
		}

		/// <summary>
		/// Return encryption algorithm used to secure the store and its entries.
		/// </summary>
		/// <returns> the encryption algorithm to use. </returns>
		public virtual EncryptionAlgorithm getStoreEncryptionAlgorithm()
		{
			return encAlg;
		}

		/// <summary>
		/// Return encryption algorithm used to secure the store and its entries.
		/// </summary>
		/// <returns> the encryption algorithm to use. </returns>
		public virtual MacAlgorithm getStoreMacAlgorithm()
		{
			return macAlg;
		}
	}

}