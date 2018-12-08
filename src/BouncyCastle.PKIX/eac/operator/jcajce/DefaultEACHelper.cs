namespace org.bouncycastle.eac.@operator.jcajce
{

	public class DefaultEACHelper : EACHelper
	{
		public override Signature createSignature(string type)
		{
			return Signature.getInstance(type);
		}
	}

}