namespace org.bouncycastle.eac.jcajce
{

	public class NamedEACHelper : EACHelper
	{
		private readonly string providerName;

		public NamedEACHelper(string providerName)
		{
			this.providerName = providerName;
		}

		public virtual KeyFactory createKeyFactory(string type)
		{
			return KeyFactory.getInstance(type, providerName);
		}
	}
}