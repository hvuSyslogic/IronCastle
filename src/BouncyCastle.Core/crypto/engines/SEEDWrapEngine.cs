namespace org.bouncycastle.crypto.engines
{
	/// <summary>
	/// An implementation of the SEED key wrapper based on RFC 4010/RFC 3394.
	/// <para>
	/// For further details see: <a href="http://www.ietf.org/rfc/rfc4010.txt">http://www.ietf.org/rfc/rfc4010.txt</a>.
	/// </para>
	/// </summary>
	public class SEEDWrapEngine : RFC3394WrapEngine
	{
		public SEEDWrapEngine() : base(new SEEDEngine())
		{
		}
	}

}