namespace org.bouncycastle.asn1.x9
{
	/// <summary>
	/// A holding class that allows for X9ECParameters to be lazily constructed.
	/// </summary>
	public abstract class X9ECParametersHolder
	{
		private X9ECParameters @params;

		public virtual X9ECParameters getParameters()
		{
			lock (this)
			{
				if (@params == null)
				{
					@params = createParameters();
				}
        
				return @params;
			}
		}

		public abstract X9ECParameters createParameters();
	}

}