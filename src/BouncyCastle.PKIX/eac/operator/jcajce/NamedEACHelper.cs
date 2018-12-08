namespace org.bouncycastle.eac.@operator.jcajce
{

	public class NamedEACHelper : EACHelper
	{
		private readonly string providerName;

		public NamedEACHelper(string providerName)
		{
			this.providerName = providerName;
		}

		public override Signature createSignature(string type)
		{
			return Signature.getInstance(type, providerName);
		}
	}
}