namespace org.bouncycastle.jce.provider
{

	/// @deprecated use org.bouncycastle.jcajce.config.PKCS12StoreParameter 
	public class JDKPKCS12StoreParameter : KeyStore.LoadStoreParameter
	{
		private OutputStream outputStream;
		private KeyStore.ProtectionParameter protectionParameter;
		private bool useDEREncoding;

		public virtual OutputStream getOutputStream()
		{
			return outputStream;
		}

		public virtual KeyStore.ProtectionParameter getProtectionParameter()
		{
			return protectionParameter;
		}

		public virtual bool isUseDEREncoding()
		{
			return useDEREncoding;
		}

		public virtual void setOutputStream(OutputStream outputStream)
		{
			this.outputStream = outputStream;
		}

		public virtual void setPassword(char[] password)
		{
			this.protectionParameter = new KeyStore.PasswordProtection(password);
		}

		public virtual void setProtectionParameter(KeyStore.ProtectionParameter protectionParameter)
		{
			this.protectionParameter = protectionParameter;
		}

		public virtual void setUseDEREncoding(bool useDEREncoding)
		{
			this.useDEREncoding = useDEREncoding;
		}
	}

}