namespace org.bouncycastle.openssl
{
	/// <summary>
	/// call back to allow a password to be fetched when one is requested. </summary>
	/// @deprecated no longer used. 
	public interface PasswordFinder
	{
		char[] getPassword();
	}

}