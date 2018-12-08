namespace org.bouncycastle.eac.@operator.jcajce
{

	public class ProviderEACHelper : EACHelper
	{
		private readonly Provider provider;

		public ProviderEACHelper(Provider provider)
		{
			this.provider = provider;
		}

		public override Signature createSignature(string type)
		{
			return Signature.getInstance(type, provider);
		}
	}
}