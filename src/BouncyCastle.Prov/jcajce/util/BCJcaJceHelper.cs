namespace org.bouncycastle.jcajce.util
{

	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;

	/// <summary>
	/// A JCA/JCE helper that refers to the BC provider for all it's needs.
	/// </summary>
	public class BCJcaJceHelper : ProviderJcaJceHelper
	{
		private static volatile Provider bcProvider;

		private static Provider getBouncyCastleProvider()
		{
			if (Security.getProvider("BC") != null)
			{
				return Security.getProvider("BC");
			}
			else if (bcProvider != null)
			{
				return bcProvider;
			}
			else
			{
				bcProvider = new BouncyCastleProvider();

				return bcProvider;
			}
		}

		public BCJcaJceHelper() : base(getBouncyCastleProvider())
		{
		}
	}

}