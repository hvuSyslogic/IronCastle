namespace org.bouncycastle.est.jcajce
{

	/// <summary>
	/// Channel Binding Provider provides a method of extracting the
	/// ChannelBinding that can be customised specifically for the provider.
	/// Presently JSSE does not support RFC 5920.
	/// <para>
	/// See https://bugs.openjdk.java.net/browse/JDK-6491070
	/// </para>
	/// </summary>
	public interface ChannelBindingProvider
	{
		bool canAccessChannelBinding(Socket sock);

		byte[] getChannelBinding(Socket sock, string binding);
	}

}