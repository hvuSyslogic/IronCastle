namespace org.bouncycastle.crypto.engines
{
	/// <summary>
	/// An implementation of the Camellia key wrapper based on RFC 3657/RFC 3394.
	/// <para>
	/// For further details see: <a href="http://www.ietf.org/rfc/rfc3657.txt">http://www.ietf.org/rfc/rfc3657.txt</a>.
	/// </para>
	/// </summary>
	public class CamelliaWrapEngine : RFC3394WrapEngine
	{
		public CamelliaWrapEngine() : base(new CamelliaEngine())
		{
		}
	}

}