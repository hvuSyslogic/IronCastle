namespace org.bouncycastle.jcajce
{

	/// <summary>
	/// LoadStoreParameter to allow for additional config with PKCS12 files.
	/// <para>
	/// Note: if you want a straight DER encoding of a PKCS#12 file you should use this.
	/// </para>
	/// </summary>
	public class PKCS12StoreParameter : KeyStore.LoadStoreParameter
	{
		private readonly OutputStream @out;
		private readonly KeyStore.ProtectionParameter protectionParameter;
		private readonly bool forDEREncoding;

		public PKCS12StoreParameter(OutputStream @out, char[] password) : this(@out, password, false)
		{
		}

		public PKCS12StoreParameter(OutputStream @out, KeyStore.ProtectionParameter protectionParameter) : this(@out, protectionParameter, false)
		{
		}

		public PKCS12StoreParameter(OutputStream @out, char[] password, bool forDEREncoding) : this(@out, new KeyStore.PasswordProtection(password), forDEREncoding)
		{
		}

		public PKCS12StoreParameter(OutputStream @out, KeyStore.ProtectionParameter protectionParameter, bool forDEREncoding)
		{
			this.@out = @out;
			this.protectionParameter = protectionParameter;
			this.forDEREncoding = forDEREncoding;
		}

		public virtual OutputStream getOutputStream()
		{
			return @out;
		}

		public virtual KeyStore.ProtectionParameter getProtectionParameter()
		{
			return protectionParameter;
		}

		/// <summary>
		/// Return whether the KeyStore used with this parameter should be DER encoded on saving.
		/// </summary>
		/// <returns> true for straight DER encoding, false otherwise, </returns>
		public virtual bool isForDEREncoding()
		{
			return forDEREncoding;
		}
	}

}