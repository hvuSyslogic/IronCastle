namespace org.bouncycastle.est.jcajce
{

	/// <summary>
	/// Implementations provide SSL socket factories.
	/// </summary>
	public interface SSLSocketFactoryCreator
	{
		SSLSocketFactory createFactory();

		bool isTrusted();
	}

}