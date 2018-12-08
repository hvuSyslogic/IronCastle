namespace org.bouncycastle.eac.jcajce
{

	public class ProviderEACHelper : EACHelper
	{
		private readonly Provider provider;

		public ProviderEACHelper(Provider provider)
		{
			this.provider = provider;
		}

		public virtual KeyFactory createKeyFactory(string type)
		{
			return KeyFactory.getInstance(type, provider);
		}
	}
}