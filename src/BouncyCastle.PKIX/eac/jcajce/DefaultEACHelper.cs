namespace org.bouncycastle.eac.jcajce
{

	public class DefaultEACHelper : EACHelper
	{
		public virtual KeyFactory createKeyFactory(string type)
		{
			return KeyFactory.getInstance(type);
		}
	}

}