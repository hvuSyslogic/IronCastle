using org.bouncycastle.jcajce;

namespace org.bouncycastle.jcajce.provider.config
{

	/// @deprecated use org.bouncycastle.jcajce.PKCS12StoreParameter 
	public class PKCS12StoreParameter : PKCS12StoreParameter
	{
		public PKCS12StoreParameter(OutputStream @out, char[] password) : base(@out, password, false)
		{
		}

		public PKCS12StoreParameter(OutputStream @out, KeyStore.ProtectionParameter protectionParameter) : base(@out, protectionParameter, false)
		{
		}

		public PKCS12StoreParameter(OutputStream @out, char[] password, bool forDEREncoding) : base(@out, new KeyStore.PasswordProtection(password), forDEREncoding)
		{
		}

		public PKCS12StoreParameter(OutputStream @out, KeyStore.ProtectionParameter protectionParameter, bool forDEREncoding) : base(@out, protectionParameter, forDEREncoding)
		{
		}
	}

}