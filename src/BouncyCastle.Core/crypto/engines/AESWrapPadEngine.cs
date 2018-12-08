namespace org.bouncycastle.crypto.engines
{
	public class AESWrapPadEngine : RFC5649WrapEngine
	{
		public AESWrapPadEngine() : base(new AESEngine())
		{
		}
	}

}