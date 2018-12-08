namespace org.bouncycastle.jcajce
{

	public class BCLoadStoreParameter : KeyStore.LoadStoreParameter
	{
		private readonly InputStream @in;
		private readonly OutputStream @out;
		private readonly KeyStore.ProtectionParameter protectionParameter;

		/// <summary>
		/// Base constructor for
		/// </summary>
		/// <param name="out"> </param>
		/// <param name="password"> </param>
		public BCLoadStoreParameter(OutputStream @out, char[] password) : this(@out, new KeyStore.PasswordProtection(password))
		{
		}

		public BCLoadStoreParameter(InputStream @in, char[] password) : this(@in, new KeyStore.PasswordProtection(password))
		{
		}

		public BCLoadStoreParameter(InputStream @in, KeyStore.ProtectionParameter protectionParameter) : this(@in, null, protectionParameter)
		{
		}

		public BCLoadStoreParameter(OutputStream @out, KeyStore.ProtectionParameter protectionParameter) : this(null, @out, protectionParameter)
		{
		}

		public BCLoadStoreParameter(InputStream @in, OutputStream @out, KeyStore.ProtectionParameter protectionParameter)
		{
			this.@in = @in;
			this.@out = @out;
			this.protectionParameter = protectionParameter;
		}

		public virtual KeyStore.ProtectionParameter getProtectionParameter()
		{
			return protectionParameter;
		}

		public virtual OutputStream getOutputStream()
		{
			if (@out == null)
			{
				throw new UnsupportedOperationException("parameter not configured for storage - no OutputStream");
			}

			return @out;
		}

		public virtual InputStream getInputStream()
		{
			if (@out != null)
			{
				throw new UnsupportedOperationException("parameter configured for storage OutputStream present");
			}

			return @in;
		}
	}

}