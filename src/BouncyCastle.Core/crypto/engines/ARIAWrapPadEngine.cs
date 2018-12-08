namespace org.bouncycastle.crypto.engines
{
	public class ARIAWrapPadEngine : RFC5649WrapEngine
	{
		public ARIAWrapPadEngine() : base(new ARIAEngine())
		{
		}
	}

}